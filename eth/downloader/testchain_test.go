// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package downloader

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// Test chain parameters.
var (
	testKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddress = crypto.PubkeyToAddress(testKey.PublicKey)
	testUiHash  = crypto.Keccak256Hash([]byte("Ui Hash"))
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
	contractAbi      = "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"readAccount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"writeAccount\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"writeBalance\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"}]"
	contractByteCode = "0x608060405234801561001057600080fd5b5061011c806100206000396000f3fe60806040526004361060305760003560e01c80634beb781b1460355780635caba0a414603f578063b073feae146075575b600080fd5b603d47600055565b005b348015604a57600080fd5b506063605636600460b8565b6001600160a01b03163190565b60405190815260200160405180910390f35b603d608036600460b8565b6040516001600160a01b038216903480156108fc02916000818181858888f1935050505015801560b4573d6000803e3d6000fd5b5050565b60006020828403121560c957600080fd5b81356001600160a01b038116811460df57600080fd5b939250505056fea26469706673582212201a2e8dccd918b8e5fd96f44115a97fc0d96c792a220a76cd1f2ec216db835b7664736f6c634300080d0033"
)

type chainSet struct {
	base *testChain

	// Different forks on top of the base chain:
	forkLightA *testChain
	forkLightB *testChain
	forkHeavy  *testChain

	config *params.ChainConfig
}

var testChainSet *chainSet
var testChainSetWithEthanos *chainSet

var pregenerated bool

func init() {
	// Reduce some of the parameters to make the tester faster
	fullMaxForkAncestry = 10000
	lightMaxForkAncestry = 10000
	blockCacheMaxItems = 1024
	fsHeaderSafetyNet = 256
	fsHeaderContCheck = 500 * time.Millisecond

	testChainGenerator := func(config *params.ChainConfig) *chainSet {
		db := rawdb.NewMemoryDatabase()

		gspec := &core.Genesis{
			Config:  config,
			Alloc:   core.GenesisAlloc{testAddress: {Balance: big.NewInt(100000000000000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
		}
		genesis := gspec.MustCommit(db, trie.NewDatabase(db, trie.HashDefaults))

		set := chainSet{
			config: config,
			base:   newTestChain(config, db, blockCacheMaxItems+200, genesis),
		}

		var forkLen = int(fullMaxForkAncestry + 50)
		var wg sync.WaitGroup

		// Generate the test chains to seed the peers with
		set.forkLightA = set.base.makeFork(config, db, forkLen, false, 1)
		set.forkLightB = set.base.makeFork(config, db, forkLen, false, 2)
		set.forkHeavy = set.base.makeFork(config, db, forkLen, true, 3)

		// Generate the test peers used by the tests to avoid overloading during testing.
		// These seemingly random chains are used in various downloader tests. We're just
		// pre-generating them here.
		chains := []*testChain{
			set.base,
			set.forkLightA,
			set.forkLightB,
			set.forkHeavy,
			set.base.shorten(1),
			set.base.shorten(blockCacheMaxItems - 15),
			set.base.shorten((blockCacheMaxItems - 15) / 2),
			set.base.shorten(blockCacheMaxItems - 15 - 5),
			set.base.shorten(MaxHeaderFetch),
			set.base.shorten(800),
			set.base.shorten(800 / 2),
			set.base.shorten(800 / 3),
			set.base.shorten(800 / 4),
			set.base.shorten(800 / 5),
			set.base.shorten(800 / 6),
			set.base.shorten(800 / 7),
			set.base.shorten(800 / 8),
			set.base.shorten(3*fsHeaderSafetyNet + 256 + fsMinFullBlocks),
			set.base.shorten(fsMinFullBlocks + 256 - 1),
			set.forkLightA.shorten(len(set.base.blocks) + 80),
			set.forkLightB.shorten(len(set.base.blocks) + 81),
			set.forkLightA.shorten(len(set.base.blocks) + MaxHeaderFetch),
			set.forkLightB.shorten(len(set.base.blocks) + MaxHeaderFetch),
			set.forkHeavy.shorten(len(set.base.blocks) + 79),
		}
		wg.Add(len(chains) * 2)
		for _, chain := range chains {
			go func(blocks []*types.Block) {
				newTestBlockchain(gspec, rawdb.HashScheme, blocks)
				wg.Done()
			}(chain.blocks[1:])
			go func(blocks []*types.Block) {
				newTestBlockchain(gspec, rawdb.PathScheme, blocks)
				wg.Done()
			}(chain.blocks[1:])
		}
		wg.Wait()
		return &set
	}

	testChainSet = testChainGenerator(params.NewTestChainConfig().SetTestSweepEpoch(400000))
	testChainSetWithEthanos = testChainGenerator(params.NewTestChainConfig().SetTestSweepEpoch(400))
	// Mark the chains pregenerated. Generating a new one will lead to a panic.
	pregenerated = true
}

type testChain struct {
	blocks []*types.Block
}

// newTestChain creates a blockchain of the given length.
func newTestChain(config *params.ChainConfig, db ethdb.Database, length int, genesis *types.Block) *testChain {
	tc := &testChain{
		blocks: []*types.Block{genesis},
	}
	tc.generate(config, db, length-1, 0, genesis, false)
	return tc
}

// makeFork creates a fork on top of the test chain.
func (tc *testChain) makeFork(config *params.ChainConfig, db ethdb.Database, length int, heavy bool, seed byte) *testChain {
	fork := tc.copy(len(tc.blocks) + length)
	fork.generate(config, db, length, seed, tc.blocks[len(tc.blocks)-1], heavy)
	return fork
}

// shorten creates a copy of the chain with the given length. It panics if the
// length is longer than the number of available blocks.
func (tc *testChain) shorten(length int) *testChain {
	if length > len(tc.blocks) {
		panic(fmt.Errorf("can't shorten test chain to %d blocks, it's only %d blocks long", length, len(tc.blocks)))
	}
	return tc.copy(length)
}

func (tc *testChain) copy(newlen int) *testChain {
	if newlen > len(tc.blocks) {
		newlen = len(tc.blocks)
	}
	cpy := &testChain{
		blocks: append([]*types.Block{}, tc.blocks[:newlen]...),
	}
	return cpy
}

// generate creates a chain of n blocks starting at and including parent.
// the returned hash chain is ordered head->parent. In addition, every 22th block
// contains a transaction and every 5th an uncle to allow testing correct block
// reassembly.
func (tc *testChain) generate(config *params.ChainConfig, db ethdb.Database, n int, seed byte, parent *types.Block, heavy bool) {
	var overwriteContract common.Address
	blocks, _ := core.GenerateChain(config, parent, ethash.NewFaker(), db, n, func(i int, block *core.BlockGen) {
		block.SetCoinbase(common.Address{seed})
		// If a heavy chain is requested, delay blocks to raise difficulty
		if heavy {
			block.OffsetTime(-9)
		}
		signer := types.MakeSigner(config, block.Number(), block.Timestamp())
		// Include transactions to the miner to make blocks more interesting.
		if parent == tc.blocks[0] {
			if i%22 == 0 {
				tx := types.NewTransaction(block.TxNonce(testAddress), common.Address{seed}, big.NewInt(1000), params.TxGas, block.BaseFee(), nil)
				block.AddTx(signTx(tx, signer, testKey))
			} else if i%37 == 0 {
				packCreateWithUiParams, err := packCreateWithUiHash([]byte(contractByteCode), testUiHash)
				if err != nil {
					panic(err)
				}
				tx := types.NewTransaction(block.TxNonce(testAddress), common.CreateWithUiHashAddress, big.NewInt(1000), 1000000, block.BaseFee(), packCreateWithUiParams)
				block.AddTx(signTx(tx, signer, testKey))
			}
		}
		if i%29 == 0 {
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    block.TxNonce(testAddress),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: block.BaseFee(),
				Data:     common.FromHex(contractByteCode),
			})
			block.AddTx(signTx(tx, signer, testKey))

			contractAddr := crypto.CreateAddress(testAddress, tx.Nonce())
			tx = types.NewTransaction(
				block.TxNonce(testAddress),
				contractAddr,
				big.NewInt(0),
				3000000,
				block.BaseFee(),
				createWriteBalanceInput(),
			)
			block.AddTx(signTx(tx, signer, testKey))
		}

		if block.Number().Uint64() == 1 {
			tx := types.NewTx(&types.LegacyTx{
				Nonce:    block.TxNonce(testAddress),
				To:       nil,
				Value:    big.NewInt(0),
				Gas:      300000,
				GasPrice: block.BaseFee(),
				Data:     common.FromHex(contractByteCode),
			})
			block.AddTx(signTx(tx, signer, testKey))
		}

		if block.Number().Uint64()%config.SweepEpoch == 7 {
			overwriteContract = crypto.CreateAddress(testAddress, 1)
			tx := types.NewTransaction(
				block.TxNonce(testAddress),
				overwriteContract,
				big.NewInt(int64(block.Number().Uint64()/config.SweepEpoch+1)),
				300000,
				block.BaseFee(),
				createWriteBalanceInput(),
			)
			block.AddTx(signTx(tx, signer, testKey))
		}
		// if the block number is a multiple of 5, add a bonus uncle to the block
		if i > 0 && i%5 == 0 {
			var ckptRoot common.Hash
			parent := block.PrevBlock(i - 2)
			if config.IsCheckpoint(parent.NumberU64()) {
				ckptRoot = parent.Root()
			} else {
				ckptRoot = parent.CheckpointRoot()
			}
			block.AddUncle(&types.Header{
				ParentHash:     parent.Hash(),
				Number:         big.NewInt(parent.Number().Int64() + 1),
				CheckpointRoot: ckptRoot,
			})
		}
	}, func(number uint64) *types.Header {
		if int(number) >= len(tc.blocks) {
			return nil
		}
		return tc.blocks[number].Header()
	})
	tc.blocks = append(tc.blocks, blocks...)
}

var (
	testBlockchainsHash = make(map[common.Hash]*testBlockchain)
	testBlockchainsPath = make(map[common.Hash]*testBlockchain)
	testBlockchainsLock sync.Mutex
)

func packCreateWithUiHash(contractCode []byte, uiHash common.Hash) ([]byte, error) {
	bytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}

	arguments := abi.Arguments{
		{Type: bytesTy},   // contract deployment bytecode
		{Type: bytes32Ty}, // ui bytecode hash
	}

	packed, err := arguments.Pack(contractCode, uiHash)
	if err != nil {
		return nil, err
	}

	return packed, nil
}

type testBlockchain struct {
	chain *core.BlockChain
	gen   sync.Once
}

// newTestBlockchain creates a blockchain database built by running the given blocks,
// either actually running them, or reusing a previously created one. The returned
// chains are *shared*, so *do not* mutate them.
func newTestBlockchain(gspec *core.Genesis, scheme string, blocks []*types.Block) *core.BlockChain {
	// Retrieve an existing database, or create a new one
	head := gspec.ToBlock().Hash()
	if len(blocks) > 0 {
		head = blocks[len(blocks)-1].Hash()
	}
	cacheConfig := &core.CacheConfig{
		TrieCleanLimit: 256,
		TrieDirtyLimit: 256,
		TrieTimeLimit:  5 * time.Minute,
		SnapshotLimit:  256,
		SnapshotWait:   true,
		StateScheme:    scheme,
		EpochLimit:     2,
	}
	testBlockchainsLock.Lock()
	var tbc *testBlockchain
	if scheme == rawdb.HashScheme {
		if _, ok := testBlockchainsHash[head]; !ok {
			testBlockchainsHash[head] = new(testBlockchain)
		}
		tbc = testBlockchainsHash[head]
	} else {
		if _, ok := testBlockchainsPath[head]; !ok {
			testBlockchainsPath[head] = new(testBlockchain)
		}
		tbc = testBlockchainsPath[head]
	}
	testBlockchainsLock.Unlock()

	// Ensure that the database is generated
	tbc.gen.Do(func() {
		if pregenerated {
			panic("Requested chain generation outside of init")
		}
		chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), cacheConfig, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
		if err != nil {
			panic(err)
		}
		if n, err := chain.InsertChain(blocks); err != nil {
			fmt.Println("inserted", len(blocks), "blocks")
			panic(fmt.Sprintf("block %d: %v", n, err))
		}
		tbc.chain = chain
	})
	return tbc.chain
}

func signTx(tx *types.Transaction, signer types.Signer, prv *ecdsa.PrivateKey) *types.Transaction {
	tx, err := types.SignTx(tx, types.HomesteadSigner{}, prv)
	if err != nil {
		panic(err)
	}

	return tx
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
