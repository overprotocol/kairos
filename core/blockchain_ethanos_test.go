// Copyright 2024 The kairos Authors
// This file is part of the kairos library.
//
// The kairos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The kairos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the kairos library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

/*
pragma solidity ^0.8.0;

	contract AccountAccessor {
	    uint256 private balance; //storage slot is 0

	    function writeBalance() public payable {
	        balance = address(this).balance;
	    }

	    function readAccount(address addr) public returns (uint256) {
	        return addr.balance;
	    }

	    function writeAccount(address addr) public payable {
	        payable(addr).transfer(msg.value);
	    }
	}
*/
const (
	contractAbi       = "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"readAccount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"writeAccount\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"writeBalance\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"}]"
	contractByteCode  = "0x608060405234801561001057600080fd5b5061011c806100206000396000f3fe60806040526004361060305760003560e01c80634beb781b1460355780635caba0a414603f578063b073feae146075575b600080fd5b603d47600055565b005b348015604a57600080fd5b506063605636600460b8565b6001600160a01b03163190565b60405190815260200160405180910390f35b603d608036600460b8565b6040516001600160a01b038216903480156108fc02916000818181858888f1935050505015801560b4573d6000803e3d6000fd5b5050565b60006020828403121560c957600080fd5b81356001600160a01b038116811460df57600080fd5b939250505056fea26469706673582212201a2e8dccd918b8e5fd96f44115a97fc0d96c792a220a76cd1f2ec216db835b7664736f6c634300080d0033"
	testEpoch         = 200
	factoryByteCode   = "608060405234801561001057600080fd5b50610241806100206000396000f3fe608060405234801561001057600080fd5b506004361061002a5760003560e01c80627743601461002f575b600080fd5b610049600480360381019061004491906100d8565b61004b565b005b6000808251602084016000f59050803b61006457600080fd5b5050565b600061007b61007684610146565b610121565b905082815260208101848484011115610097576100966101eb565b5b6100a2848285610177565b509392505050565b600082601f8301126100bf576100be6101e6565b5b81356100cf848260208601610068565b91505092915050565b6000602082840312156100ee576100ed6101f5565b5b600082013567ffffffffffffffff81111561010c5761010b6101f0565b5b610118848285016100aa565b91505092915050565b600061012b61013c565b90506101378282610186565b919050565b6000604051905090565b600067ffffffffffffffff821115610161576101606101b7565b5b61016a826101fa565b9050602081019050919050565b82818337600083830152505050565b61018f826101fa565b810181811067ffffffffffffffff821117156101ae576101ad6101b7565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600080fd5b600080fd5b600080fd5b600080fd5b6000601f19601f830116905091905056fea2646970667358221220ea8b35ed310d03b6b3deef166941140b4d9e90ea2c92f6b41eb441daf49a59c364736f6c63430008070033"
	fcontractByteCode = "6080604052348015600f57600080fd5b5060646000819055506081806100266000396000f3fe608060405260043610601f5760003560e01c80632b68b9c614602a576025565b36602557005b600080fd5b60306032565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffea2646970667358221220ab749f5ed1fcb87bda03a74d476af3f074bba24d57cb5a355e8162062ad9a4e664736f6c63430008070033"
)

var (
	key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	key3, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	addr1   = crypto.PubkeyToAddress(key1.PublicKey)
	addr2   = crypto.PubkeyToAddress(key2.PublicKey)
	addr3   = crypto.PubkeyToAddress(key3.PublicKey)
)

type BlockGenerator struct {
	db          ethdb.Database
	chainConfig *params.ChainConfig
	blocks      []*types.Block
}

func createBlockGenerator(depositContract bool) *BlockGenerator {
	chainConfig := *params.AllEthashProtocolChanges
	chainConfig.SweepEpoch = testEpoch
	genDb := rawdb.NewMemoryDatabase()
	gspec := &Genesis{
		Config:  &chainConfig,
		Alloc:   GenesisAlloc{addr1: {Balance: big.NewInt(params.Ether)}},
		BaseFee: big.NewInt(0),
	}
	if depositContract {
		gspec.Alloc[params.DepositContractAddress] = GenesisAccount{Balance: big.NewInt(params.Ether)}
	}
	gspec.MustCommit(genDb, trie.NewDatabase(genDb, nil))
	return &BlockGenerator{
		db:          genDb,
		chainConfig: &chainConfig,
		blocks:      []*types.Block{gspec.ToBlock()},
	}
}

func (bg *BlockGenerator) createBlockList(n int, gen func(int, *BlockGen)) []*types.Block {
	chain, _ := bg.createBlockListWithReceipt(n, gen)
	return chain
}

func (bg *BlockGenerator) createBlockListWithReceipt(n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	currentBlock := bg.blocks[len(bg.blocks)-1]
	chain, receipt := GenerateChain(
		bg.chainConfig,
		currentBlock,
		ethash.NewFaker(),
		bg.db,
		n,
		func(i int, bg *BlockGen) {
			bg.SetCoinbase(addr1)
			gen(i, bg)
		},
		func(number uint64) *types.Header {
			if int(number) >= len(bg.blocks) {
				return nil
			}
			return bg.blocks[number].Header()
		},
	)
	bg.blocks = append(bg.blocks, chain...)
	return chain, receipt
}

func createBlockChain(snapshots, depositContract bool, scheme string) *BlockChain {
	db := rawdb.NewMemoryDatabase()

	var config = &CacheConfig{
		TrieCleanLimit: 256,
		TrieDirtyLimit: 256,
		TrieTimeLimit:  5 * time.Minute,
		SnapshotLimit:  128,
		StateScheme:    scheme,
		EpochLimit:     0,
	}

	if !snapshots {
		config.SnapshotLimit = 0
	}

	chainConfig := *params.AllEthashProtocolChanges
	chainConfig.SweepEpoch = testEpoch
	gspec := &Genesis{
		Config:  &chainConfig,
		Alloc:   GenesisAlloc{addr1: {Balance: big.NewInt(params.Ether)}},
		BaseFee: big.NewInt(0),
	}
	if depositContract {
		gspec.Alloc[params.DepositContractAddress] = GenesisAccount{Balance: big.NewInt(params.Ether)}
	}

	blockchain, err := NewBlockChain(db, config, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		panic(err)
	}

	return blockchain
}

func signTx(tx *types.Transaction, prv *ecdsa.PrivateKey) *types.Transaction {
	tx, err := types.SignTx(tx, types.HomesteadSigner{}, prv)
	if err != nil {
		panic(err)
	}

	return tx
}

func signRestorationTx(tx *types.Transaction, prv *ecdsa.PrivateKey) *types.Transaction {
	tx, err := types.SignTx(tx, types.NewAlpacaSigner(tx.ChainId()), prv)
	if err != nil {
		panic(err)
	}

	return tx
}

func countAccount(blockchain *BlockChain) int {
	trie, err := openAccountTrie(blockchain)
	if err != nil {
		panic(err)
	}

	it, err := trie.NodeIterator(nil)
	if err != nil {
		panic(err)
	}
	return countIterator(it)
}

func countStorage(blockchain *BlockChain, addr common.Address, hash common.Hash) int {
	trie, err := openStorageTrie(blockchain, addr, hash)
	if err != nil {
		panic(err)
	}

	it, err := trie.NodeIterator(nil)
	if err != nil {
		panic(err)
	}
	return countIterator(it)
}

func countIterator(it trie.NodeIterator) int {
	count := 0
	for it.Next(true) {
		if it.Leaf() {
			count++
		}
	}
	return count
}

func openAccountTrie(bc *BlockChain) (state.Trie, error) {
	state, err := bc.State()
	if err != nil {
		return nil, err
	}

	root := state.IntermediateRoot(false)
	return state.Database().OpenTrie(root, state.GetCurrentEpoch())
}

func openStorageTrie(bc *BlockChain, addr common.Address, hash common.Hash) (state.Trie, error) {
	state, err := bc.State()
	if err != nil {
		return nil, err
	}

	root := state.IntermediateRoot(false)
	return state.Database().OpenStorageTrie(root, state.GetCurrentEpoch(), addr, hash, nil)
}

type proofBytes [][]byte

func (n *proofBytes) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

func (n *proofBytes) Delete(key []byte) error {
	panic("not supported")
}

func getAccountProof(epoch uint32, root common.Hash, addr common.Address, triedb *trie.Database) (proofBytes, error) {
	tr, err := trie.NewStateTrie(trie.StateTrieID(root, epoch), triedb)
	if err != nil {
		return nil, err
	}
	var accountProof proofBytes
	addrHash := crypto.Keccak256Hash(addr.Bytes())
	if err := tr.Prove(addrHash[:], &accountProof); err != nil {
		return nil, err
	}
	return accountProof, nil
}

func getRestorationProof(bc *BlockChain, target common.Address, targetEpoch uint32) ([]byte, error) {
	var proofs [][][]byte
	epochCoverage := getCurrentEpochCoverage(bc, target)
	for epochCoverage > targetEpoch {
		bn, _ := bc.Config().CalcLastCheckpointBlockNumber(epochCoverage)
		header := bc.GetHeaderByNumber(bn)
		state, err := bc.StateAtWithoutCheckpoint(header)
		if err != nil {
			return nil, err
		}
		proof, err := getAccountProof(epochCoverage-1, header.Root, target, bc.triedb)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)

		if state.Exist(target) {
			epochCoverage = state.GetEpochCoverage(target)
		} else {
			epochCoverage--
		}
	}
	restorationProof, err := rlp.EncodeToBytes(proofs)
	if err != nil {
		return nil, err
	}
	return restorationProof, nil
}

func getStorageRoot(bc *BlockChain, addr common.Address) common.Hash {
	state, err := bc.State()
	if err != nil {
		panic(err)
	}

	return state.GetStorageRoot(addr)
}

func getBalance(bc *BlockChain, addr common.Address) uint64 {
	state, err := bc.State()
	if err != nil {
		panic(err)
	}

	return state.GetBalance(addr).Uint64()
}

func createWriteBalanceInput() []byte {
	cabi, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		panic(err)
	}

	input, err := cabi.Pack("writeBalance")
	if err != nil {
		panic(err)
	}

	return input
}

func createWriteAccountInput(addr common.Address) []byte {
	cabi, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		panic(err)
	}

	input, err := cabi.Pack("writeAccount", addr)
	if err != nil {
		panic(err)
	}

	return input
}

func createReadAccountInput(addr common.Address) []byte {
	cabi, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		panic(err)
	}

	input, err := cabi.Pack("readAccount", addr)
	if err != nil {
		panic(err)
	}

	return input
}

func getCurrentEpochCoverage(bc *BlockChain, addr common.Address) uint32 {
	currentState, _ := bc.State()
	return currentState.GetEpochCoverage(addr)
}

func isMissingTrieNodeErr(err error) bool {
	if err == nil {
		return false
	}

	return strings.HasPrefix(err.Error(), "missing trie node")
}

func shouldPanic(t *testing.T, f func()) {
	defer func() { recover() }()
	f()
	t.Errorf("should have panicked")
}

/*
When epoch passes, the current state must go to the checkpointed state
and the current state should be an empty trie.
*/
func TestEthanosScenario1(t *testing.T) {
	testEthanosScenario1(t, false, rawdb.HashScheme)
	testEthanosScenario1(t, false, rawdb.PathScheme)
}
func TestEthanosScenario1WithSnapshots(t *testing.T) {
	testEthanosScenario1(t, true, rawdb.HashScheme)
	testEthanosScenario1(t, true, rawdb.PathScheme)
}

func testEthanosScenario1(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// adding addr2 state to the current epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-1, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then current trie has 2 leaves
	if cnt := countAccount(bc); cnt != 2 {
		t.Errorf("Current Trie should have 2 account(addr1, addr2) but %d", cnt)
	}

	// when passed to the next epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	bn := bc.CurrentBlock().Number.Uint64()
	if stateRoot, ckptRoot := bc.GetBlockByNumber(bn-1).Root(), bc.CurrentBlock().CheckpointRoot; stateRoot != ckptRoot {
		t.Errorf("Checkpoint root in header should be same with the root of checkpointed header. but %s != %s", stateRoot.Hex(), ckptRoot.Hex())
	}

	// then trie has 1 leaf. because old leaf were passed to checkpointed trie.
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}
}

/*
storage trie should not go to the checkpointed state.
*/
func TestEthanosScenario2(t *testing.T) {
	testEthanosScenario2(t, false, rawdb.HashScheme)
	testEthanosScenario2(t, false, rawdb.PathScheme)
}
func TestEthanosScenario2WithSnapshots(t *testing.T) {
	testEthanosScenario2(t, true, rawdb.HashScheme)
	testEthanosScenario2(t, true, rawdb.PathScheme)
}

func testEthanosScenario2(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-1, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    gen.TxNonce(addr1),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: nil,
				Data:     common.FromHex(contractByteCode),
			})
			gen.AddTx(signTx(tx, key1))

			contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), 3000000, nil, createWriteBalanceInput()),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	storageRoot := getStorageRoot(bc, contractAddr)

	// then there are 3 accounts(addr1, contract). contract account has storage trie.
	if cnt := countAccount(bc); cnt != 2 {
		t.Errorf("Current Trie should have 2 account(addr1, contract) but %d", cnt)
	}

	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when passed to the next epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	// then trie has 1 leaf and because old leaf were passed to checkpointed trie.
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}

	// then storage trie should not empty
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}
}

/*
If the state that exists only in the checkpointed state is used for update by tx,
the current state to the state must be stored.
*/
func TestEthanosScenario3(t *testing.T) {
	testEthanosScenario3(t, false, rawdb.HashScheme)
	testEthanosScenario3(t, false, rawdb.PathScheme)
}
func TestEthanosScenario3WithSnapshots(t *testing.T) {
	testEthanosScenario3(t, true, rawdb.HashScheme)
	testEthanosScenario3(t, true, rawdb.PathScheme)
}

func testEthanosScenario3(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when put balance into addr2 and pass the epoch.
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-1, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}
	// then there are 2 accounts(addr1, addr2)
	if cnt := countAccount(bc); cnt != 2 {
		t.Errorf("Current Trie should have 2 account(addr1, addr2) but %d", cnt)
	}

	// when Deploy Contract and create write transaction for addr2
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(4, func(i int, gen *BlockGen) {
		switch i {
		case 3:
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    gen.TxNonce(addr1),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: nil,
				Data:     common.FromHex(contractByteCode),
			})
			gen.AddTx(signTx(tx, key1))

			contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), 3000000, nil, createWriteAccountInput(addr2)),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there should be 3 accounts(addr1, contract, addr2)
	if cnt := countAccount(bc); cnt != 3 {
		t.Errorf("Current Trie should have 3 account(addr1, contract, addr2) but %d", cnt)
	}

	// then balance should have 15000 in 10000(from the previous epoch) + 5000 (by tx)
	if balance := getBalance(bc, addr2); balance != 15000 {
		t.Errorf("addr2 has 15000 balance but %d", balance)
	}
}

/*
If the state that exists only in the checkpointed state is read by tx,
the current state must store the state.
*/
func TestEthanosScenario4(t *testing.T) {
	testEthanosScenario4(t, false, rawdb.HashScheme)
	testEthanosScenario4(t, false, rawdb.PathScheme)
}
func TestEthanosScenario4WithSnapshots(t *testing.T) {
	testEthanosScenario4(t, true, rawdb.HashScheme)
	testEthanosScenario4(t, true, rawdb.PathScheme)
}

func testEthanosScenario4(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when put balance into addr2 and pass the epoch.
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there is 1 account(addr1)
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}

	// when Deploy Contract and create read transaction for addr2
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    gen.TxNonce(addr1),
			To:       nil,
			Value:    big.NewInt(0),
			Gas:      300000,
			GasPrice: nil,
			Data:     common.FromHex(contractByteCode),
		})
		gen.AddTx(signTx(tx, key1))

		contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
		gen.AddTx(signTx(
			types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(0), 3000000, nil, createReadAccountInput(addr2)),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there should be 3 accounts(addr1, contract, addr2)
	if cnt := countAccount(bc); cnt != 3 {
		t.Errorf("Current Trie should have 3 account(addr1, contract, addr2) but %d", cnt)
	}

	// then balance should have 10000(from the previous epoch)
	if balance := getBalance(bc, addr2); balance != 10000 {
		t.Errorf("addr2 has 10000 balance but %d", balance)
	}
}

/*
If the state that exists in old state(not checkpointed state, not current state) is read by tx,
the current state should not store the state
*/
func TestEthanosScenario5(t *testing.T) {
	testEthanosScenario5(t, false, rawdb.HashScheme)
	testEthanosScenario5(t, false, rawdb.PathScheme)
}
func TestEthanosScenario5WithSnapshots(t *testing.T) {
	testEthanosScenario5(t, true, rawdb.HashScheme)
	testEthanosScenario5(t, true, rawdb.PathScheme)
}

func testEthanosScenario5(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when put balance into addr2 and pass the epoch.
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there is 1 accounts(addr1)
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}

	// when Deploy Contract and create read transaction for addr2. then pass the epoch
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 1:
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    gen.TxNonce(addr1),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: nil,
				Data:     common.FromHex(contractByteCode),
			})
			gen.AddTx(signTx(tx, key1))

			contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(0), 3000000, nil, createReadAccountInput(addr2)),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there should be 2 accounts(addr1, contract)
	if cnt := countAccount(bc); cnt != 2 {
		t.Errorf("Current Trie should have 2 account(addr1, contract) but %d", cnt)
	}

	// then addr2's balance should be 0
	if balance := getBalance(bc, addr2); balance != 0 {
		t.Errorf("addr2 has 0 balance but %d", balance)
	}
}

/*
If the state that exists in old state(not checkpointed state, not current state) is updated by tx,
the current state should not merged with old state
*/
func TestEthanosScenario6(t *testing.T) {
	testEthanosScenario6(t, false, rawdb.HashScheme)
	testEthanosScenario6(t, false, rawdb.PathScheme)
}
func TestEthanosScenario6WithSnapshots(t *testing.T) {
	testEthanosScenario6(t, true, rawdb.HashScheme)
	testEthanosScenario6(t, true, rawdb.PathScheme)
}

func testEthanosScenario6(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when put balance into addr2 and pass the epoch.
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there is 1 account(addr1)
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}

	if balance := getBalance(bc, addr2); balance != 10000 {
		t.Errorf("addr2 has 10000 balance but %d", balance)
	}

	// when Deploy Contract and create write transaction for addr2
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(2*testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case 2*testEpoch - 2:
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    gen.TxNonce(addr1),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: nil,
				Data:     common.FromHex(contractByteCode),
			})
			gen.AddTx(signTx(tx, key1))

			contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), 3000000, nil, createWriteAccountInput(addr2)),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there should be only one account(addr1)
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}

	// then addr2's balance should be 5000. because old state is gone
	if balance := getBalance(bc, addr2); balance != 5000 {
		t.Errorf("addr2 has 5000 balance but %d", balance)
	}
}

/*
storage trie should not removed
*/
func TestEthanosScenario7(t *testing.T) {
	testEthanosScenario7(t, false, rawdb.HashScheme)
	testEthanosScenario7(t, false, rawdb.PathScheme)
}
func TestEthanosScenario7WithSnapshots(t *testing.T) {
	testEthanosScenario7(t, true, rawdb.HashScheme)
	testEthanosScenario7(t, true, rawdb.PathScheme)
}

func testEthanosScenario7(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-1, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    gen.TxNonce(addr1),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: nil,
				Data:     common.FromHex(contractByteCode),
			})
			gen.AddTx(signTx(tx, key1))

			contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
			tx = types.NewTransaction(
				gen.TxNonce(addr1),
				contractAddr,
				big.NewInt(5000),
				3000000,
				nil,
				createWriteBalanceInput(),
			)
			gen.AddTx(signTx(tx, key1))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	storageRoot := getStorageRoot(bc, contractAddr)

	// then there is non empty storage trie
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when passed to the next epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*3, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	// then there is non empty storage trie
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}
}

/*
If the tx, that restores a state object from checkpointed state, is reverted,
the state object have to be stored only in checkpointed state
*/
func TestEthanosScenario8(t *testing.T) {
	testEthanosScenario8(t, false, rawdb.HashScheme)
	testEthanosScenario8(t, false, rawdb.PathScheme)
}
func TestEthanosScenario8WithSnapshots(t *testing.T) {
	testEthanosScenario8(t, true, rawdb.HashScheme)
	testEthanosScenario8(t, true, rawdb.PathScheme)
}

func testEthanosScenario8(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}
	// then there is 1 account(addr1)
	if cnt := countAccount(bc); cnt != 1 {
		t.Errorf("Current Trie should have only one account(addr1) but %d", cnt)
	}

	// when Deploy Contract and create a transaction that access addr2 but have insufficient gas limit
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    gen.TxNonce(addr1),
			To:       nil,
			Value:    big.NewInt(0),
			Gas:      300000,
			GasPrice: nil,
			Data:     common.FromHex(contractByteCode),
		})
		gen.AddTx(signTx(tx, key1))

		contractAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())

		// revert transaction
		insufficientGas := uint64(21432)
		gen.AddTx(signTx(
			types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(0), insufficientGas, nil, createReadAccountInput(addr2)),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there should be 2 accounts(addr1, contract), tx that access addr2 is reverted
	if cnt := countAccount(bc); cnt != 2 {
		t.Errorf("Current Trie should have 2 account(addr1, contract) but %d", cnt)
	}

	// then balance should have 10000(from the previous epoch)
	if balance := getBalance(bc, addr2); balance != 10000 {
		t.Errorf("addr2 has 15000 balance but %d", balance)
	}

	// Create a transaction that access addr2 and have sufficient gas limit
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// revert transaction
		sufficientGas := uint64(3000000)
		gen.AddTx(signTx(
			types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), sufficientGas, nil, createWriteAccountInput(addr2)),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then there should be 3 accounts(addr1, contract, addr2)
	if cnt := countAccount(bc); cnt != 3 {
		t.Errorf("Current Trie should have 3 account(addr1, contract, addr2) but %d", cnt)
	}

	// then balance should have 15000 in 10000(from the previous epoch) + 5000 (by tx)
	if balance := getBalance(bc, addr2); balance != 15000 {
		t.Errorf("addr2 has 15000 balance but %d", balance)
	}
}

/*
Check if restoration transaction restores account data until the epoch genesis
*/
func TestEthanosScenario9(t *testing.T) {
	testEthanosScenario9(t, false, rawdb.HashScheme)
	testEthanosScenario9(t, false, rawdb.PathScheme)
}
func TestEthanosScenario9WithSnapshots(t *testing.T) {
	testEthanosScenario9(t, true, rawdb.HashScheme)
	testEthanosScenario9(t, true, rawdb.PathScheme)
}

func testEthanosScenario9(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ = bc.State()
	if balance := state.GetBalance(addr2); balance.Int64() != amount*5-restoreFeeAmount {
		t.Errorf("current balance must be %d but %d", amount*5-restoreFeeAmount, balance.Int64())
	}
	if epochCoverage := state.GetEpochCoverage(addr2); epochCoverage != 0 {
		t.Errorf("current epochCoverage must be %d but %d", epochNeedToRestore, epochCoverage)
	}
	if feeAmount := state.GetBalance(addr3); feeAmount.Int64() != restoreFeeAmount {
		t.Errorf("restoreFee must be %d but %d", restoreFeeAmount, feeAmount.Int64())
	}
	if restoredNonce := state.GetNonce(addr2); restoredNonce != 5 {
		t.Errorf("restored nonce must be %d but %d", 5, restoredNonce)
	}
}

/*
Check if restoration transaction restores account data until epoch 2
*/
func TestEthanosScenario10(t *testing.T) {
	testEthanosScenario10(t, false, rawdb.HashScheme)
	testEthanosScenario10(t, false, rawdb.PathScheme)
}
func TestEthanosScenario10WithSnapshots(t *testing.T) {
	testEthanosScenario10(t, true, rawdb.HashScheme)
	testEthanosScenario10(t, true, rawdb.PathScheme)
}

func testEthanosScenario10(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(1)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ = bc.State()
	if balance := state.GetBalance(addr2); balance.Int64() != amount*4-restoreFeeAmount {
		t.Errorf("current balance must be %d but %d", amount*4-restoreFeeAmount, balance.Int64())
	}
	if epochCoverage := state.GetEpochCoverage(addr2); epochCoverage != epochNeedToRestore {
		t.Errorf("current epochCoverage must be %d but %d", epochNeedToRestore, epochCoverage)
	}
	if feeAmount := state.GetBalance(addr3); feeAmount.Int64() != restoreFeeAmount {
		t.Errorf("restoreFee must be %d but %d", restoreFeeAmount, feeAmount.Int64())
	}
	if restoredNonce := state.GetNonce(addr2); restoredNonce != 4 {
		t.Errorf("restored nonce must be %d but %d", 4, restoredNonce)
	}
}

/*
Check if two restoration transactions restore account data
*/
func TestEthanosScenario11(t *testing.T) {
	testEthanosScenario11(t, false, rawdb.HashScheme)
	testEthanosScenario11(t, false, rawdb.PathScheme)
}
func TestEthanosScenario11WithSnapshots(t *testing.T) {
	testEthanosScenario11(t, true, rawdb.HashScheme)
	testEthanosScenario11(t, true, rawdb.PathScheme)
}

func testEthanosScenario11(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(4)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ = bc.State()
	if balance := state.GetBalance(addr2); balance.Int64() != amount*2-restoreFeeAmount {
		t.Errorf("current balance must be %d but %d", amount*2-restoreFeeAmount, balance.Int64())
	}
	if epochCoverage := state.GetEpochCoverage(addr2); epochCoverage != epochNeedToRestore {
		t.Errorf("current epochCoverage must be %d but %d", epochNeedToRestore, epochCoverage)
	}
	if feeAmount := state.GetBalance(addr3); feeAmount.Int64() != restoreFeeAmount {
		t.Errorf("restoreFee must be %d but %d", restoreFeeAmount, feeAmount.Int64())
	}
	if restoredNonce := state.GetNonce(addr2); restoredNonce != 2 {
		t.Errorf("restored nonce must be %d but %d", 2, restoredNonce)
	}

	epochNeedToRestore = 0

	input, err = getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}

	restoreData, _ = types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ = bc.State()
	if balance := state.GetBalance(addr2); balance.Int64() != amount*5-restoreFeeAmount*2 {
		t.Errorf("current balance must be %d but %d", amount*5-restoreFeeAmount*2, balance.Int64())
	}
	if epochCoverage := state.GetEpochCoverage(addr2); epochCoverage != epochNeedToRestore {
		t.Errorf("current epochCoverage must be %d but %d", epochNeedToRestore, epochCoverage)
	}
	if feeAmount := state.GetBalance(addr3); feeAmount.Int64() != restoreFeeAmount*2 {
		t.Errorf("restoreFee must be %d but %d", restoreFeeAmount, feeAmount.Int64())
	}
	if restoredNonce := state.GetNonce(addr2); restoredNonce != 5 {
		t.Errorf("restored nonce must be %d but %d", 5, restoredNonce)
	}
}

/*
Check restoration transaction restores account using fee delegation
*/
func TestEthanosScenario12(t *testing.T) {
	testEthanosScenario12(t, false, rawdb.HashScheme)
	testEthanosScenario12(t, false, rawdb.PathScheme)
}
func TestEthanosScenario12WithSnapshots(t *testing.T) {
	testEthanosScenario12(t, true, rawdb.HashScheme)
	testEthanosScenario12(t, true, rawdb.PathScheme)
}

func testEthanosScenario12(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		case testEpoch*10 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr3, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key3,
	)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ = bc.State()
	if balance := state.GetBalance(addr2); balance.Int64() != amount*5 {
		t.Errorf("current balance must be %d but %d", amount*5, balance.Int64())
	}
	if epochCoverage := state.GetEpochCoverage(addr2); epochCoverage != 0 {
		t.Errorf("current epochCoverage must be %d but %d", epochNeedToRestore, epochCoverage)
	}
	// feeAmount is current balance of addr3 minus `amount` because addr3 already has `amount` before restoration
	// and feeAmount is zero because feePayer and feeRecipient is same
	if feeAmount := new(big.Int).Sub(state.GetBalance(addr3), big.NewInt(amount)); feeAmount.Int64() != 0 {
		t.Errorf("restoreFee must be %d but %d", 0, feeAmount.Int64())
	}
	if restoredNonce := state.GetNonce(addr2); restoredNonce != 5 {
		t.Errorf("restored nonce must be %d but %d", 5, restoredNonce)
	}
}

/*
Check restoration transaction restores account without fee recipient
*/
func TestEthanosScenario13(t *testing.T) {
	testEthanosScenario13(t, false, rawdb.HashScheme)
	testEthanosScenario13(t, false, rawdb.PathScheme)
}
func TestEthanosScenario13WithSnapshots(t *testing.T) {
	testEthanosScenario13(t, true, rawdb.HashScheme)
	testEthanosScenario13(t, true, rawdb.PathScheme)
}

func testEthanosScenario13(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(10000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			nil,
			nil,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ = bc.State()
	if balance := state.GetBalance(addr2); balance.Int64() != amount*5 {
		t.Errorf("current balance must be %d but %d", amount*5, balance.Int64())
	}
	if epochCoverage := state.GetEpochCoverage(addr2); epochCoverage != 0 {
		t.Errorf("current epochCoverage must be %d but %d", epochNeedToRestore, epochCoverage)
	}
	if restoredNonce := state.GetNonce(addr2); restoredNonce != 5 {
		t.Errorf("restored nonce must be %d but %d", 5, restoredNonce)
	}
}

/*
Check if restoration transaction fails if chainId mismatch
*/
func TestEthanosScenario14(t *testing.T) {
	testEthanosScenario14(t, false, rawdb.HashScheme)
	testEthanosScenario14(t, false, rawdb.PathScheme)
}
func TestEthanosScenario14WithSnapshots(t *testing.T) {
	testEthanosScenario14(t, true, rawdb.HashScheme)
	testEthanosScenario14(t, true, rawdb.PathScheme)
}

func testEthanosScenario14(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	chainConfig := bc.chainConfig
	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			new(big.Int).Add(chainConfig.ChainID, common.Big1), // mismatched chainID
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(chainConfig),
		key2,
	)

	_, receipts := blockGenerator.createBlockListWithReceipt(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})

	if receipts[0][0].Status != types.ReceiptStatusFailed {
		t.Errorf("transaction must be reverted because of chainId mismatch")
	}
}

/*
Check if restoration transaction fails when there is mismatch between the epoch sender request to restore and proof for the epoch
*/
func TestEthanosScenario15(t *testing.T) {
	testEthanosScenario15(t, false, rawdb.HashScheme)
	testEthanosScenario15(t, false, rawdb.PathScheme)
}
func TestEthanosScenario15WithSnapshots(t *testing.T) {
	testEthanosScenario15(t, true, rawdb.HashScheme)
	testEthanosScenario15(t, true, rawdb.PathScheme)
}

func testEthanosScenario15(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(1)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	var proofs [][][]byte
	epochCoverage := getCurrentEpochCoverage(bc, addr2)
	for epochCoverage > 4 {
		bn, _ := bc.Config().CalcLastCheckpointBlockNumber(epochCoverage)
		header := bc.GetHeaderByNumber(bn)
		state, err := bc.StateAtWithoutCheckpoint(header)
		if err != nil {
			t.Errorf("fail to load state: %v\n", err)
		}
		proof, _ := getAccountProof(epochCoverage-1, header.Root, addr2, bc.triedb)
		proofs = append(proofs, proof)

		if state.Exist(addr2) {
			epochCoverage = state.GetEpochCoverage(addr2)
		} else {
			epochCoverage--
		}
	}
	input, _ := rlp.EncodeToBytes(proofs)
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	_, receipts := blockGenerator.createBlockListWithReceipt(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})

	if receipts[0][0].Status != types.ReceiptStatusFailed {
		t.Errorf("transaction must be reverted because of mismatch between the epoch to restore and proofs")
	}
}

/*
Check if restoration transaction fails when the restoration fee is higher than the amount restored
*/
func TestEthanosScenario16(t *testing.T) {
	testEthanosScenario16(t, false, rawdb.HashScheme)
	testEthanosScenario16(t, false, rawdb.PathScheme)
}
func TestEthanosScenario16WithSnapshots(t *testing.T) {
	testEthanosScenario16(t, true, rawdb.HashScheme)
	testEthanosScenario16(t, true, rawdb.PathScheme)
}

func testEthanosScenario16(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(1)
	amount := int64(10000)
	restoreFeeAmount := int64(1000000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(10*testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	_, receipts := blockGenerator.createBlockListWithReceipt(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})

	if receipts[0][0].Status != types.ReceiptStatusFailed {
		t.Errorf("transaction must be reverted because of insufficient balance for restoration fee")
	}
}

/*
Check if restoration transaction fails when the restoration data is expired
*/
func TestEthanosScenario17(t *testing.T) {
	testEthanosScenario17(t, false, rawdb.HashScheme)
	testEthanosScenario17(t, false, rawdb.PathScheme)
}
func TestEthanosScenario17WithSnapshots(t *testing.T) {
	testEthanosScenario17(t, true, rawdb.HashScheme)
	testEthanosScenario17(t, true, rawdb.PathScheme)
}

func testEthanosScenario17(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2)-1,
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	_, receipts := blockGenerator.createBlockListWithReceipt(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})

	if receipts[0][0].Status != types.ReceiptStatusFailed {
		t.Errorf("transaction must be reverted because of expired restore data")
	}
}

/*
Check if restoration transaction fails when the target is contract
*/
func TestEthanosScenario18(t *testing.T) {
	testEthanosScenario18(t, false, rawdb.HashScheme)
	testEthanosScenario18(t, false, rawdb.PathScheme)
}
func TestEthanosScenario18WithSnapshots(t *testing.T) {
	testEthanosScenario18(t, true, rawdb.HashScheme)
	testEthanosScenario18(t, true, rawdb.PathScheme)
}

func testEthanosScenario18(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(10000)
	restoreFeeAmount := int64(1000)
	var contractAddr common.Address

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*3, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			contractAddr = createStorageTrie(gen)
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, contractAddr, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			contractAddr,
			state.GetEpochCoverage(contractAddr),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	_, receipts := blockGenerator.createBlockListWithReceipt(1, func(i int, gen *BlockGen) {
		gen.AddTx(signRestorationTx(
			types.NewTx(
				&types.RestorationTx{
					ChainID:     bc.chainConfig.ChainID,
					Nonce:       gen.TxNonce(addr1),
					Gas:         100000,
					GasTipCap:   big.NewInt(1),
					GasFeeCap:   big.NewInt(1),
					To:          nil,
					Value:       big.NewInt(0),
					Data:        input,
					AccessList:  types.AccessList{},
					RestoreData: restoreData,
				},
			),
			key1,
		))
	})

	if receipts[0][0].Status != types.ReceiptStatusFailed {
		t.Errorf("transaction must be reverted because of expired restore data")
	}
}

/*
Check if restoring account with storage trie works well
*/
func TestEthanosScenario19(t *testing.T) {
	testEthanosScenario19(t, false, rawdb.HashScheme)
	testEthanosScenario19(t, false, rawdb.PathScheme)
}
func TestEthanosScenario19WithSnapshots(t *testing.T) {
	testEthanosScenario19(t, true, rawdb.HashScheme)
	testEthanosScenario19(t, true, rawdb.PathScheme)
}

func testEthanosScenario19(t *testing.T, snapshots bool, scheme string) {
	// given
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	var contractAddr common.Address

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			contractAddr = createStorageTrie(gen)
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, _ := bc.State()
	slot := big.NewInt(0)
	storageSlotHash := common.BytesToHash(slot.Bytes())
	balanceInVariable := state.GetCommittedState(contractAddr, storageSlotHash)
	balance := state.GetBalance(contractAddr)
	if balanceInVariable.Big().Cmp(balance) != 0 {
		t.Errorf("balanceInContract be %d but %d", balance.Int64(), balanceInVariable.Big().Uint64())
	}
}

/*
Check if restoration transaction fails if to and value is non-nil
*/
func TestEthanosScenario20(t *testing.T) {
	testEthanosScenario20(t, false, rawdb.HashScheme)
	testEthanosScenario20(t, false, rawdb.PathScheme)
}
func TestEthanosScenario20WithSnapshots(t *testing.T) {
	testEthanosScenario20(t, true, rawdb.HashScheme)
	testEthanosScenario20(t, true, rawdb.PathScheme)
}

func testEthanosScenario20(t *testing.T, snapshots bool, scheme string) {
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	epochNeedToRestore := uint32(0)
	amount := int64(params.GWei) * 1e8
	restoreFeeAmount := int64(1000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	input, err := getRestorationProof(bc, addr2, epochNeedToRestore)
	if err != nil {
		t.Errorf("fail to get restoration proof: %v\n", err)
	}
	state, err := bc.State()
	if err != nil {
		t.Errorf("fail to get state: %v\n", err)
	}

	restoreData, _ := types.SignRestoreData(
		types.NewRestoreData(
			bc.chainConfig.ChainID,
			addr2,
			state.GetEpochCoverage(addr2),
			epochNeedToRestore,
			big.NewInt(restoreFeeAmount),
			&addr3,
		),
		types.LatestRestoreDataSigner(bc.chainConfig),
		key2,
	)

	nonEmptyValue := big.NewInt(1)
	shouldPanic(t,
		func() {
			blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
				gen.AddTx(signRestorationTx(
					types.NewTx(
						&types.RestorationTx{
							ChainID:     bc.chainConfig.ChainID,
							Nonce:       gen.TxNonce(addr1),
							Gas:         100000,
							GasTipCap:   nil,
							GasFeeCap:   nil,
							To:          nil,
							Value:       nonEmptyValue,
							Data:        input,
							AccessList:  types.AccessList{},
							RestoreData: restoreData,
						},
					),
					key1,
				))
			})
		},
	)

	nonEmptyTo := addr1
	shouldPanic(t,
		func() {
			blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
				gen.AddTx(signRestorationTx(
					types.NewTx(
						&types.RestorationTx{
							ChainID:     bc.chainConfig.ChainID,
							Nonce:       gen.TxNonce(addr1),
							Gas:         100000,
							GasTipCap:   nil,
							GasFeeCap:   nil,
							To:          &nonEmptyTo,
							Value:       big.NewInt(0),
							Data:        input,
							AccessList:  types.AccessList{},
							RestoreData: restoreData,
						},
					),
					key1,
				))
			})
		},
	)
}

func TestEthanosExcludeDepositContract(t *testing.T) {
	testEthanosExcludeDepositContract(t, rawdb.HashScheme)
	testEthanosExcludeDepositContract(t, rawdb.PathScheme)
}
func testEthanosExcludeDepositContract(t *testing.T, scheme string) {
	bc := createBlockChain(false, true, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(true)

	amount := int64(10000)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*10, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2, testEpoch*3 - 2, testEpoch*4 - 2, testEpoch*6 - 2, testEpoch*9 - 2:
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr2), addr1, big.NewInt(0), params.TxGas, nil, nil),
				key2,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}
	state, err := bc.StateAtWithoutCheckpoint(bc.CurrentHeader())
	if err != nil {
		t.Errorf("fail to load state: %v\n", err)
	}
	if state.Empty(params.DepositContractAddress) {
		t.Errorf("deposit contract must not be swept")
	}
}

/*
Test access contract at the first block of the epoch

*/

func TestEthanosContractAtFirstBlock(t *testing.T) {
	testEthanosContractAtFirstBlock(t, false, rawdb.HashScheme)
	testEthanosContractAtFirstBlock(t, false, rawdb.PathScheme)
}

func TestEthanosContractAtFirstBlockWithSnapshots(t *testing.T) {
	testEthanosContractAtFirstBlock(t, true, rawdb.HashScheme)
	testEthanosContractAtFirstBlock(t, true, rawdb.PathScheme)
}

func testEthanosContractAtFirstBlock(t *testing.T, snapshots bool, scheme string) {
	bc := createBlockChain(snapshots, true, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(true)

	amount := int64(10000)
	var contractAddr common.Address

	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-1, func(i int, gen *BlockGen) {
		switch i {
		case testEpoch - 2:
			contractAddr = createStorageTrie(gen)
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(amount), params.TxGas, nil, nil),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signTx(
			types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), 3000000, nil, createWriteBalanceInput()),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}
}

/*
Test old state (before current - TriesInMemory blocks) is not accessible
*/
func TestEthanosStateGCShouldGCOldState(t *testing.T) {
	testEthanosStateGCShouldGCOldState(t, false)
}
func TestEthanosStateGCShouldGCOldStateWithSnapshots(t *testing.T) {
	testEthanosStateGCShouldGCOldState(t, true)
}

func testEthanosStateGCShouldGCOldState(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	// long enough length to pass checkpoint but less than (sweepEpoch + TriesInMemory)
	length := testEpoch + TriesInMemory/2
	if i, err := bc.InsertChain(blockGenerator.createBlockList(length, func(i int, gen *BlockGen) {
		gen.AddTx(signTx(
			types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(1000), params.TxGas, nil, nil),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	for i := 1; i < length-1; i++ {
		// when get state with StateAtWithoutCheckpoint
		header := bc.GetHeaderByNumber(uint64(i))
		_, err := bc.StateAtWithoutCheckpoint(header)

		if i > length-TriesInMemory || bc.Config().IsCheckpoint(uint64(i)) {
			// then return state without nil if state is recent state or checkpointed state
			if err != nil {
				t.Errorf("Unexpected Error: %v", err)
			}
		} else {
			// then return error if state is old state
			if !isMissingTrieNodeErr(err) {
				t.Errorf("Expected error is missing trie node. but err is %v", err)
			}
		}
	}
}

func CheckCommitted(bc *BlockChain, number uint64) bool {
	header := bc.GetHeaderByNumber(number)
	if !bc.HasState(header) {
		return false
	}
	epoch := bc.chainConfig.CalcEpoch(header.Number.Uint64())
	rootNode := rawdb.ReadLegacyAccountTrieNode(bc.db, epoch, header.Root)
	return rootNode != nil
}

/*
Commit trigger by 2 cases
1. inserted block is checkpoint block
2. when it hasn't been committed for a long time
this test check case 2
*/
func TestEthanosStateCommitmentTriggeredByTrieTimeLimit(t *testing.T) {
	testEthanosStateCommitmentTriggeredByTrieTimeLimit(t, false)
}
func TestEthanosStateCommitmentTriggeredByTrieTimeLimitWithSnapshots(t *testing.T) {
	testEthanosStateCommitmentTriggeredByTrieTimeLimit(t, true)
}

func testEthanosStateCommitmentTriggeredByTrieTimeLimit(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	length := testEpoch + 157 // 157 is random number
	if i, err := bc.InsertChain(blockGenerator.createBlockList(length, func(i int, gen *BlockGen) {
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// when commit triggered by trie time limit
	bc.gcproc += bc.cacheConfig.TrieTimeLimit

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then blockchain should commit state trie of block length - TriesInMemory + 1
	// because if gc triggered by trie time limit, it commits before `TriesInMemory` block
	if committed := CheckCommitted(bc, uint64(length-TriesInMemory+1)); !committed {
		t.Errorf("state trie should be committed")
	}
}

/*
Commit trigger by 2 cases
1. inserted block is checkpoint block
2. when it hasn't been committed for a long time
this test check case 1
*/
func TestEthanosCkptStateCommitment(t *testing.T) {
	testEthanosCkptStateCommitment(t, false)
}
func TestEthanosCkptStateCommitmentWithSnapshot(t *testing.T) {
	testEthanosCkptStateCommitment(t, true)
}

func testEthanosCkptStateCommitment(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	length := testEpoch - 1
	if i, err := bc.InsertChain(blockGenerator.createBlockList(length, func(i int, gen *BlockGen) {
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// when commit triggered by random commit block
	testLength := 153 // 153 is random number
	bc.ckptGcStatus.CommitBlock = uint64(testEpoch + testLength - 1)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(testLength-1, func(i int, gen *BlockGen) {
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}
	// then blockchain shouldn't commit checkpoint state trie
	if committed := CheckCommitted(bc, uint64(length)); committed {
		t.Errorf("state trie shouldn't be committed")
	}

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}
	// then blockchain should commit checkpoint state trie
	if committed := CheckCommitted(bc, uint64(length)); !committed {
		t.Errorf("state trie should be committed")
	}
}

/*
	Tests for Storage Trie GC
*/

// Create Storage Trie. It means creating contract code (with contract's local storage)
func createStorageTrie(gen *BlockGen) common.Address {
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    gen.TxNonce(addr1),
		To:       nil,
		Value:    big.NewInt(0),
		Gas:      300000,
		GasPrice: nil,
		Data:     common.FromHex(contractByteCode),
	})
	gen.AddTx(signTx(tx, key1))

	contractAddr := crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
	gen.AddTx(signTx(
		types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), 100000, nil, createWriteBalanceInput()),
		key1,
	))

	return contractAddr
}

/*
Even if gc has occurred (past the `TiresInMemory` block),
the storage tree associated with the account in the current block should not be garbage collected.
1. Create Storage Trie
2. Trigger GC
3. Commit
*/
func TestEthanosStorageTrieAccessibilityWhenGCOccurs(t *testing.T) {
	testEthanosStorageTrieAccessibilityWhenGCOccurs(t, false)
}
func TestEthanosStorageTrieAccessibilityWhenGCOccursWithSnapshots(t *testing.T) {
	testEthanosStorageTrieAccessibilityWhenGCOccurs(t, true)
}

func testEthanosStorageTrieAccessibilityWhenGCOccurs(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	length := testEpoch - TriesInMemory - 3
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(length, func(i int, gen *BlockGen) {
		if i == length-2 {
			contractAddr = createStorageTrie(gen)
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	storageRoot := getStorageRoot(bc, contractAddr)

	// then contract account has storage trie.
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when passed `TriesInMemory` blocks for trigger gc
	if i, err := bc.InsertChain(blockGenerator.createBlockList(TriesInMemory, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	// then storage trie should not empty (gc should not affected to storage trie)
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when commit occurs (by checkpoint)
	if i, err := bc.InsertChain(blockGenerator.createBlockList(3, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	// then storage trie should not empty
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when stop chain (gc all trie)
	bc.Stop()
}

/*
If it passes `TriesInMemory` blocks so account trie was garbage collected.
Storage trie which reference account `not` was garbage collected must be preserved.
So, access to that storage trie should permitted.
1. Create Storage Trie
2. Commit
3. Trigger GC
*/
func TestEthanosStorageTrieAccessibilityWhenCommitOccurs(t *testing.T) {
	testEthanosStorageTrieAccessibilityWhenCommitOccurs(t, false)
}
func TestEthanosStorageTrieAccessibilityWhenCommitOccursWithSnapshots(t *testing.T) {
	testEthanosStorageTrieAccessibilityWhenCommitOccurs(t, true)
}

func testEthanosStorageTrieAccessibilityWhenCommitOccurs(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-1, func(i int, gen *BlockGen) {
		if i == testEpoch-TriesInMemory-3 {
			contractAddr = createStorageTrie(gen)
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	storageRoot := getStorageRoot(bc, contractAddr)

	// then contract account has storage trie.
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when passed to the next epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	// then storage trie should not empty
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when passed `TriesInMemory` blocks for trigger gc
	if i, err := bc.InsertChain(blockGenerator.createBlockList(TriesInMemory, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	// then storage trie should not empty
	if cnt := countStorage(bc, contractAddr, storageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when stop chain (gc all trie)
	bc.Stop()
}

/*
1. Create Storage Trie
2. Update Storage Trie (make garbage)
3. Trigger GC
It should remove old storage trie (created at step 1)
*/
func TestEthanosStorageTrieCanBeGarbageCollected(t *testing.T) {
	testEthanosStorageTrieCanBeGarbageCollected(t, false)
}
func TestEthanosStorageTrieCanBeGarbageCollectedWithSnapshots(t *testing.T) {
	testEthanosStorageTrieCanBeGarbageCollected(t, true)
}

func testEthanosStorageTrieCanBeGarbageCollected(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-TriesInMemory-10, func(i int, gen *BlockGen) {
		if i == testEpoch-TriesInMemory-12 {
			contractAddr = createStorageTrie(gen)
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	oldStorageRoot := getStorageRoot(bc, contractAddr)

	// then contract account has storage trie.
	if cnt := countStorage(bc, contractAddr, oldStorageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when Update Storage Trie
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		gen.AddTx(signTx(
			types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(5000), 3000000, nil, createWriteBalanceInput()),
			key1,
		))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	newStorageRoot := getStorageRoot(bc, contractAddr)

	// then new storage root generated
	if oldStorageRoot == newStorageRoot {
		t.Errorf("old storage root should not equal to new storage root. (%s != %s)", oldStorageRoot, newStorageRoot)
	}

	// then storage trie should not empty
	if cnt := countStorage(bc, contractAddr, newStorageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// then old storage trie should not empty (it wasn't garbage collected yet)
	if cnt := countStorage(bc, contractAddr, oldStorageRoot); cnt == 0 {
		t.Errorf("Old Storage Trie should not empty (not garbage collected)")
	}

	// when gc occurs
	if i, err := bc.InsertChain(blockGenerator.createBlockList(TriesInMemory, func(i int, gen *BlockGen) {
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then storage trie should not empty
	if cnt := countStorage(bc, contractAddr, newStorageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// then old trie cannot be opened (garbage collected)
	if cnt := countStorage(bc, contractAddr, newStorageRoot); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when stop chain (gc all trie)
	bc.Stop()
}

/*
1. Create Storage Trie and make `large` account trie
2. Trigger Cap (for this set `TrieDirtyLimit` to 1)
Cap flush account trie node to disk.
test that if account trie node (which is related to storage trie) was flushed,
storage trie should be flushed too.
*/
func TestEthanosStorageTrieFlushedWithAccountTrieNode(t *testing.T) {
	testEthanosStorageTrieFlushedWithAccountTrieNode(t, false)
}
func TestEthanosStorageTrieFlushedWithAccountTrieNodeWithSnapshots(t *testing.T) {
	testEthanosStorageTrieFlushedWithAccountTrieNode(t, true)
}

func testEthanosStorageTrieFlushedWithAccountTrieNode(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-TriesInMemory-2, func(i int, gen *BlockGen) {
		if i == 0 {
			createStorageTrie(gen)
		} else {
			for j := 0; j < 40; j++ {
				addr := common.HexToAddress(fmt.Sprintf("0x200%d%d", i, j))
				gen.AddTx(signTx(
					types.NewTransaction(gen.TxNonce(addr1), addr, big.NewInt(1), params.TxGas, nil, nil),
					key1,
				))
			}
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// when passed to the next epoch and stop chain (gc all trie)
	bc.cacheConfig.TrieDirtyLimit = 1

	if i, err := bc.InsertChain(blockGenerator.createBlockList(TriesInMemory+3, func(i int, gen *BlockGen) {})); err != nil {
		t.Errorf("insert error (block index %d): %+v\n", i, err)
	}

	bc.Stop()
}

/*
1. create same storage trie with difference contract (differenct account node)
2. change one storage trie and trigger gc (old contract account node was garbage collected)
3. check stororage trie(generated at step 1) was not garbage collected with account node(by step 2)
*/
func TestEthanosStorageTrieGCWithMultiReference(t *testing.T) {
	testEthanosStorageTrieGCWithMultiReference(t, false)
}
func TestEthanosStorageTrieGCWithMultiReferenceWithSnapshots(t *testing.T) {
	testEthanosStorageTrieGCWithMultiReference(t, true)
}

func testEthanosStorageTrieGCWithMultiReference(t *testing.T, snapshots bool) {
	// given
	bc := createBlockChain(snapshots, false, rawdb.HashScheme)
	blockGenerator := createBlockGenerator(false)

	// when Create Contract and Storage Trie on current Epoch
	var contractAddr1, contractAddr2 common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch-TriesInMemory-10, func(i int, gen *BlockGen) {
		if i == testEpoch-TriesInMemory-12 {
			contractAddr1 = createStorageTrie(gen)
		} else if i == testEpoch-TriesInMemory-11 {
			contractAddr2 = createStorageTrie(gen)
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	oldStorageRoot1 := getStorageRoot(bc, contractAddr1)
	oldStorageRoot2 := getStorageRoot(bc, contractAddr2)

	// then differenct contract has same storage trie
	if oldStorageRoot1 != oldStorageRoot2 {
		t.Errorf("Storage root should be equals")
	}

	// when Update Storage Trie and triger gc
	if i, err := bc.InsertChain(blockGenerator.createBlockList(TriesInMemory+1, func(i int, gen *BlockGen) {
		if i == 0 {
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), contractAddr1, big.NewInt(5000), 3000000, nil, createWriteBalanceInput()),
				key1,
			))
		}
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// then new storage root generated
	newStorageRoot1 := getStorageRoot(bc, contractAddr1)
	if oldStorageRoot1 == newStorageRoot1 {
		t.Errorf("old storage root should not equal to new storage root. (%s != %s)", oldStorageRoot1, newStorageRoot1)
	}

	// then contract 2's storage trie never changed
	newStorageRoot2 := getStorageRoot(bc, contractAddr2)
	if oldStorageRoot2 != newStorageRoot2 {
		t.Errorf("Contract 2's storage trie should not changed")
	}

	// then contract 2's storage trie should not garbage collected
	if cnt := countStorage(bc, contractAddr2, newStorageRoot2); cnt == 0 {
		t.Errorf("Storage Trie should not empty")
	}

	// when stop chain (gc all trie)
	bc.Stop()
}

/*
Three possible scenarios
1. We are using Create2 at epoch 0 or 1. In this case Create2 works and we should have three accounts (addr1, factory, target contract)
2. We are using Create2 at epoch > 1 with no restoration. In this case Create2 fails and we should have three accounts (addr1, addr2, factory)
3. We are using Create2 at epoch > 1 with restoration. In this case Create2 works and we should have five accounts (addr1, addr2, addr3, facotry, target contract)
*/
func TestCreate2(t *testing.T) {
	testCreate2(t, false, rawdb.HashScheme, false, false)
	testCreate2(t, false, rawdb.PathScheme, false, false)
	testCreate2(t, false, rawdb.HashScheme, true, false)
	testCreate2(t, false, rawdb.PathScheme, true, false)
	testCreate2(t, false, rawdb.HashScheme, true, true)
	testCreate2(t, false, rawdb.PathScheme, true, true)
}

func TestCreate2WithSnapshots(t *testing.T) {
	testCreate2(t, true, rawdb.HashScheme, false, false)
	testCreate2(t, true, rawdb.PathScheme, false, false)
	testCreate2(t, true, rawdb.HashScheme, true, false)
	testCreate2(t, true, rawdb.PathScheme, true, false)
	testCreate2(t, true, rawdb.HashScheme, true, true)
	testCreate2(t, true, rawdb.PathScheme, true, true)
}

func testCreate2(t *testing.T, snapshots bool, scheme string, lateEpoch, restoration bool) {
	bc := createBlockChain(snapshots, false, scheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	var factoryAddr = common.Address{}

	// If lateEpoch is true, the epoch will be set to 2
	if lateEpoch {
		if i, err := bc.InsertChain(blockGenerator.createBlockList(testEpoch*2, func(i int, gen *BlockGen) {
			gen.AddTx(signTx(
				types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10), params.TxGas, nil, nil),
				key1,
			))
		})); err != nil {
			t.Errorf("insert error (block index %d): %v\n", i, err)
		}
	}

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    gen.TxNonce(addr1),
			To:       nil,
			Value:    big.NewInt(0),
			Gas:      300000,
			GasPrice: nil,
			Data:     common.FromHex(factoryByteCode),
		})
		gen.AddTx(signTx(tx, key1))

		factoryAddr = crypto.CreateAddress(addr1, tx.MsgEpochCoverage(), tx.MsgNonce())
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	// If restoration is true, the target contract address will be restored to epoch 0
	if restoration {
		contractAddr := crypto.CreateAddress2(factoryAddr, [32]byte{}, crypto.Keccak256(common.Hex2Bytes(fcontractByteCode)))

		epochNeedToRestore := uint32(0)
		restoreFeeAmount := int64(1000)

		input, err := getRestorationProof(bc, contractAddr, epochNeedToRestore)
		if err != nil {
			t.Errorf("fail to get restoration proof: %v\n", err)
		}
		state, err := bc.State()
		if err != nil {
			t.Errorf("fail to get state: %v\n", err)
		}

		restoreData, _ := types.SignRestoreData(
			types.NewRestoreData(
				bc.chainConfig.ChainID,
				contractAddr,
				state.GetEpochCoverage(contractAddr),
				epochNeedToRestore,
				big.NewInt(restoreFeeAmount),
				&addr3,
			),
			types.LatestRestoreDataSigner(bc.chainConfig),
			key2,
		)

		if i, err := bc.InsertChain(blockGenerator.createBlockList(2, func(i int, gen *BlockGen) {
			gen.AddTx(signRestorationTx(
				types.NewTx(
					&types.RestorationTx{
						ChainID:     bc.chainConfig.ChainID,
						Nonce:       gen.TxNonce(addr1),
						Gas:         100000,
						GasTipCap:   big.NewInt(1),
						GasFeeCap:   big.NewInt(1),
						To:          nil,
						Value:       big.NewInt(0),
						Data:        input,
						AccessList:  types.AccessList{},
						RestoreData: restoreData,
					},
				),
				key1,
			))
		})); err != nil {
			t.Errorf("insert error (block index %d): %v\n", i, err)
		}
	}

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		data := common.Hex2Bytes("00774360000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a76080604052348015600f57600080fd5b5060646000819055506081806100266000396000f3fe608060405260043610601f5760003560e01c80632b68b9c614602a576025565b36602557005b600080fd5b60306032565b005b3373ffffffffffffffffffffffffffffffffffffffff16fffea2646970667358221220ab749f5ed1fcb87bda03a74d476af3f074bba24d57cb5a355e8162062ad9a4e664736f6c6343000807003300000000000000000000000000000000000000000000000000")
		tx := types.NewTx(&types.LegacyTx{
			Nonce:    gen.TxNonce(addr1),
			To:       &factoryAddr,
			Value:    big.NewInt(0),
			Gas:      500000,
			GasPrice: nil,
			Data:     data,
		})
		gen.AddTx(signTx(tx, key1))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	targetCnt := 3
	if lateEpoch && restoration {
		targetCnt = 5
	}
	if cnt := countAccount(bc); cnt != targetCnt {
		t.Errorf("Current Trie should have %d accounts but %d", targetCnt, cnt)
	}
}
