// Copyright 2019 The go-ethereum Authors
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

package snapshot

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/triedb/hashdb"
	"github.com/ethereum/go-ethereum/trie/triedb/pathdb"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"golang.org/x/crypto/sha3"
)

func hashData(input []byte) common.Hash {
	var hasher = sha3.NewLegacyKeccak256()
	var hash common.Hash
	hasher.Reset()
	hasher.Write(input)
	hasher.Sum(hash[:0])
	return hash
}

// Tests that snapshot generation from an empty database.
func TestGeneration(t *testing.T) {
	testGeneration(t, rawdb.HashScheme)
	// testGeneration(t, rawdb.PathScheme)
}

func testGeneration(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// two of which also has the same 3-slot storage trie attached.
	var helper = newHelper(10, scheme)
	// checkpoint state
	{
		stRoot := helper.makeCkptStorageTrie(common.Hash{}, []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, false)
		ckptStRoot := helper.makeCkptStorageTrie(common.Hash{}, []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"}, false)
		helper.addCkptTrieAccount("acc-0", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptTrieAccount("acc-1-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(3), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptTrieAccount("acc-4", &types.StateAccount{Balance: big.NewInt(4), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		helper.makeCkptStorageTrie(hashData([]byte("acc-1-ckpt")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.makeCkptStorageTrie(hashData([]byte("acc-3")), []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"}, true)
		helper.makeCkptStorageTrie(hashData([]byte("acc-4")), []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"}, true)
	}
	// current state
	{
		stRoot := helper.makeCurrStorageTrie(common.Hash{}, []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, false)
		helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	}

	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	if have, want := root, common.HexToHash("0x7b3acc775699c0c69f1245e1030639a18c56c9ba44fabdc20817acd121700129"); have != want {
		t.Fatalf("have %#x want %#x", have, want)
	}
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)

	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation with existent flat state.
func TestGenerateExistentState(t *testing.T) {
	testGenerateExistentState(t, rawdb.HashScheme)
	testGenerateExistentState(t, rawdb.PathScheme)
}

func testGenerateExistentState(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// two of which also has the same 3-slot storage trie attached.
	var helper = newHelper(10, scheme)
	// checkpoint state
	{
		helper.addCkptTrieAccount("acc-0", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptSnapAccount("acc-0", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		stRoot := helper.makeCkptStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCkptTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptSnapAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-1", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

		helper.addCkptTrieAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptSnapAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		ckptStRoot := helper.makeCkptStorageTrie(hashData([]byte("acc-3")), []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"}, true)
		helper.addCkptTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptSnapAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-3", []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"})

		ckptStRoot = helper.makeCkptStorageTrie(hashData([]byte("acc-4")), []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"}, true)
		helper.addCkptTrieAccount("acc-4", &types.StateAccount{Balance: big.NewInt(3), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCkptSnapAccount("acc-4", &types.StateAccount{Balance: big.NewInt(3), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-4", []string{"key-0", "key-1", "key-2-ckpt", "key-3", "key-4"}, []string{"key-0", "val-1", "val-2", "val-3-ckpt", "val-4"})
	}
	// current state
	{
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCurrSnapAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-1", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

		helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCurrSnapAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		stRoot = helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addCurrSnapAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-3", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	}

	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)

	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

func checkSnapRoot(t *testing.T, epoch uint32, snap *diskLayer, ckptSnap *ckptDiskLayer, trieRoot, ckptTrieRoot common.Hash) {
	t.Helper()

	accIt := snap.AccountIterator(common.Hash{})
	defer accIt.Release()

	snapRoot, err := generateTrieRoot(nil, "", accIt, epoch, common.Hash{}, stackTrieGenerate,
		func(db ethdb.KeyValueWriter, accountHash, codeHash common.Hash, stat *generateStats) (common.Hash, bool, error) {
			storageIt, _ := snap.StorageIterator(accountHash, common.Hash{})
			defer storageIt.Release()

			hash, err := generateTrieRoot(nil, "", storageIt, epoch, accountHash, stackTrieGenerate, nil, stat, false)
			if err != nil {
				return common.Hash{}, false, err
			}
			return hash, false, nil
		}, newGenerateStats(), true)
	if err != nil {
		t.Fatal(err)
	}
	if snapRoot != trieRoot {
		t.Fatalf("snaproot: %#x != trieroot %#x", snapRoot, trieRoot)
	}

	if ckptSnap != nil {
		ckptAccIt := ckptSnap.AccountIterator(common.Hash{})
		defer ckptAccIt.Release()

		ckptSnapRoot, err := generateTrieRoot(nil, "", ckptAccIt, epoch-1, common.Hash{}, stackTrieGenerate,
			func(db ethdb.KeyValueWriter, accountHash, codeHash common.Hash, stat *generateStats) (common.Hash, bool, error) {
				// If the account has non-empty storage in current state
				// we don't generate the storage trie
				acc, err := snap.Account(accountHash)
				if err != nil {
					return common.Hash{}, false, err
				}
				if acc != nil {
					return common.Hash{}, true, nil
				}
				storageIt, _ := ckptSnap.StorageIterator(accountHash, common.Hash{})
				defer storageIt.Release()

				hash, err := generateTrieRoot(nil, "", storageIt, epoch-1, accountHash, stackTrieGenerate, nil, stat, false)
				if err != nil {
					return common.Hash{}, false, err
				}
				return hash, false, nil
			}, newGenerateStats(), true)
		if err != nil {
			t.Fatal(err)
		}
		if ckptSnapRoot != ckptTrieRoot {
			t.Fatalf("ckptSnapRoot: %#x != ckptTrieRoot #%x", ckptSnapRoot, ckptTrieRoot)
		}
	}

	if err := CheckDanglingStorage(snap.diskdb); err != nil {
		t.Fatalf("Detected dangling storages: %v", err)
	}
}

type testHelper struct {
	diskdb    ethdb.Database
	triedb    *trie.Database
	epoch     uint32
	accTrie   *trie.StateTrie
	ckptTrie  *trie.StateTrie
	nodes     *trienode.MergedNodeSet
	ckptNodes *trienode.MergedNodeSet
}

func newHelper(epoch uint32, scheme string) *testHelper {
	diskdb := rawdb.NewMemoryDatabase()
	config := &trie.Config{}
	if scheme == rawdb.PathScheme {
		config.PathDB = &pathdb.Config{} // disable caching
	} else {
		config.HashDB = &hashdb.Config{} // disable caching
	}
	triedb := trie.NewDatabase(diskdb, config)
	accTrie, _ := trie.NewStateTrie(trie.StateTrieID(types.EmptyRootHash, epoch), triedb)
	var ckptTrie *trie.StateTrie
	if epoch > 0 {
		ckptTrie, _ = trie.NewStateTrie(trie.StateTrieID(types.EmptyRootHash, epoch-1), triedb)
	}
	return &testHelper{
		diskdb:    diskdb,
		triedb:    triedb,
		epoch:     epoch,
		accTrie:   accTrie,
		ckptTrie:  ckptTrie,
		nodes:     trienode.NewMergedNodeSet(),
		ckptNodes: trienode.NewMergedNodeSet(),
	}
}

func (t *testHelper) addCurrTrieAccount(acckey string, acc *types.StateAccount) {
	val, _ := rlp.EncodeToBytes(acc)
	t.accTrie.MustUpdate([]byte(acckey), val)
}

func (t *testHelper) addCkptTrieAccount(acckey string, acc *types.StateAccount) {
	if t.ckptTrie == nil {
		panic("ckptTrie is nil")
	}
	val, _ := rlp.EncodeToBytes(acc)
	t.ckptTrie.MustUpdate([]byte(acckey), val)
}

func (t *testHelper) addCurrSnapAccount(acckey string, acc *types.StateAccount) {
	key := hashData([]byte(acckey))
	rawdb.WriteAccountSnapshot(t.diskdb, t.epoch, key, types.SlimAccountRLP(*acc))
}

func (t *testHelper) addCkptSnapAccount(acckey string, acc *types.StateAccount) {
	if t.epoch == 0 {
		panic("checkpoint state is not available")
	}
	key := hashData([]byte(acckey))
	rawdb.WriteAccountSnapshot(t.diskdb, t.epoch-1, key, types.SlimAccountRLP(*acc))
}

func (t *testHelper) addCurrAccount(acckey string, acc *types.StateAccount) {
	t.addCurrTrieAccount(acckey, acc)
	t.addCurrSnapAccount(acckey, acc)
}

func (t *testHelper) addCkptAccount(acckey string, acc *types.StateAccount) {
	t.addCkptTrieAccount(acckey, acc)
	t.addCkptSnapAccount(acckey, acc)
}

func (t *testHelper) addSnapStorage(accKey string, keys []string, vals []string) {
	accHash := hashData([]byte(accKey))
	for i, key := range keys {
		rawdb.WriteStorageSnapshot(t.diskdb, accHash, hashData([]byte(key)), []byte(vals[i]))
	}
}

func (t *testHelper) makeCurrStorageTrie(owner common.Hash, keys []string, vals []string, commit bool) common.Hash {
	id := trie.StorageTrieID(types.EmptyRootHash, t.epoch, owner, types.EmptyRootHash)
	stTrie, _ := trie.NewStateTrie(id, t.triedb)
	for i, k := range keys {
		stTrie.MustUpdate([]byte(k), []byte(vals[i]))
	}
	if !commit {
		return stTrie.Hash()
	}
	root, nodes, _ := stTrie.Commit(false)
	if nodes != nil {
		t.nodes.Merge(nodes)
	}
	return root
}

func (t *testHelper) makeCkptStorageTrie(owner common.Hash, keys []string, vals []string, commit bool) common.Hash {
	if t.epoch == 0 {
		panic("checkpoint state is not available")
	}
	id := trie.StorageTrieID(types.EmptyRootHash, t.epoch-1, owner, types.EmptyRootHash)
	stTrie, _ := trie.NewStateTrie(id, t.triedb)
	for i, k := range keys {
		stTrie.MustUpdate([]byte(k), []byte(vals[i]))
	}
	if !commit {
		return stTrie.Hash()
	}
	root, nodes, _ := stTrie.Commit(false)
	if nodes != nil {
		t.ckptNodes.Merge(nodes)
	}
	return root
}

func (t *testHelper) Commit() (common.Hash, common.Hash) {
	ckptRoot := types.EmptyRootHash
	if t.ckptTrie != nil {
		var ckptNodes *trienode.NodeSet
		ckptRoot, ckptNodes, _ = t.ckptTrie.Commit(true)
		if ckptNodes != nil {
			t.ckptNodes.Merge(ckptNodes)
		}
		t.triedb.Update(ckptRoot, types.EmptyRootHash, t.epoch-1, 0, t.ckptNodes, nil)
		t.triedb.Commit(ckptRoot, false)
	}

	root, nodes, _ := t.accTrie.Commit(true)
	if nodes != nil {
		t.nodes.Merge(nodes)
	}
	t.triedb.Update(root, ckptRoot, t.epoch, 0, t.nodes, nil)
	t.triedb.Commit(root, false)
	return root, ckptRoot
}

func (t *testHelper) CommitAndGenerate() (common.Hash, common.Hash, *diskLayer, *ckptDiskLayer) {
	root, ckptRoot := t.Commit()
	snap := generateSnapshot(t.diskdb, t.triedb, 16, t.epoch, root, ckptRoot, nil)
	return root, ckptRoot, snap, snap.ckptLayer
}

// Tests that snapshot generation with existent flat state, where the flat state
// contains some errors:
// - the contract with empty storage root but has storage entries in the disk
// - the contract with non empty storage root but empty storage slots
// - the contract(non-empty storage) misses some storage slots
//   - miss in the beginning
//   - miss in the middle
//   - miss in the end
//
// - the contract(non-empty storage) has wrong storage slots
//   - wrong slots in the beginning
//   - wrong slots in the middle
//   - wrong slots in the end
//
// - the contract(non-empty storage) has extra storage slots
//   - extra slots in the beginning
//   - extra slots in the middle
//   - extra slots in the end
func TestGenerateExistentStateWithWrongStorage(t *testing.T) {
	testGenerateExistentStateWithWrongStorage(t, rawdb.HashScheme)
	testGenerateExistentStateWithWrongStorage(t, rawdb.PathScheme)
}

func testGenerateExistentStateWithWrongStorage(t *testing.T, scheme string) {
	helper := newHelper(10, scheme)

	// checkpoint state
	{
		// Account one, empty root but non-empty database
		helper.addCkptAccount("acc-1-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-1-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"})

		// Account two, non empty root but empty database
		stRoot := helper.makeCkptStorageTrie(hashData([]byte("acc-2-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		helper.addCkptAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		// Miss slots
		{
			// Account three, non empty root but misses slots in the beginning
			helper.makeCkptStorageTrie(hashData([]byte("acc-3-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-3-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-3-ckpt", []string{"key-2-ckpt", "key-3-ckpt"}, []string{"val-2-ckpt", "val-3-ckpt"})

			// Account four, non empty root but misses slots in the middle
			helper.makeCkptStorageTrie(hashData([]byte("acc-4-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-4-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-4-ckpt", []string{"key-1-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-3-ckpt"})

			// Account five, non empty root but misses slots in the end
			helper.makeCkptStorageTrie(hashData([]byte("acc-5-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-5-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-5-ckpt", []string{"key-1-ckpt", "key-2-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt"})
		}

		// Wrong storage slots
		{
			// Account six, non empty root but wrong slots in the beginning
			helper.makeCkptStorageTrie(hashData([]byte("acc-6-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-6-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-6-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"badval-1-ckpt", "val-2-ckpt", "val-3-ckpt"})

			// Account seven, non empty root but wrong slots in the middle
			helper.makeCkptStorageTrie(hashData([]byte("acc-7-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-7-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-7-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "badval-2-ckpt", "val-3-ckpt"})

			// Account eight, non empty root but wrong slots in the end
			helper.makeCkptStorageTrie(hashData([]byte("acc-8-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-8-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-8-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "badval-3-ckpt"})

			// Account 9, non empty root but rotated slots
			helper.makeCkptStorageTrie(hashData([]byte("acc-9-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-9-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-9-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-3-ckpt", "val-2-ckpt"})
		}

		// Extra storage slots
		{
			// Account 10, non empty root but extra slots in the beginning
			helper.makeCkptStorageTrie(hashData([]byte("acc-10-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-10-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-10-ckpt", []string{"key-0-ckpt", "key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-0-ckpt", "val-1-ckpt", "val-2-ckpt", "val-3-ckpt"})

			// Account 11, non empty root but extra slots in the middle
			helper.makeCkptStorageTrie(hashData([]byte("acc-11-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-11-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-11-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-2-1-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-2-1-ckpt", "val-3-ckpt"})

			// Account 12, non empty root but extra slots in the end
			helper.makeCkptStorageTrie(hashData([]byte("acc-12-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
			helper.addCkptAccount("acc-12-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-12-ckpt", []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt", "key-4-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt", "val-4-ckpt"})
		}
	}
	// current state
	{
		// Account one, empty root but non-empty database
		helper.addCurrAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		helper.addSnapStorage("acc-1", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

		// Account two, non empty root but empty database
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-2")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCurrAccount("acc-2", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

		// Miss slots
		{
			// Account three, non empty root but misses slots in the beginning
			helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-3", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-3", []string{"key-2", "key-3"}, []string{"val-2", "val-3"})

			// Account four, non empty root but misses slots in the middle
			helper.makeCurrStorageTrie(hashData([]byte("acc-4")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-4", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-4", []string{"key-1", "key-3"}, []string{"val-1", "val-3"})

			// Account five, non empty root but misses slots in the end
			helper.makeCurrStorageTrie(hashData([]byte("acc-5")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-5", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-5", []string{"key-1", "key-2"}, []string{"val-1", "val-2"})
		}

		// Wrong storage slots
		{
			// Account six, non empty root but wrong slots in the beginning
			helper.makeCurrStorageTrie(hashData([]byte("acc-6")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-6", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-6", []string{"key-1", "key-2", "key-3"}, []string{"badval-1", "val-2", "val-3"})

			// Account seven, non empty root but wrong slots in the middle
			helper.makeCurrStorageTrie(hashData([]byte("acc-7")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-7", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-7", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "badval-2", "val-3"})

			// Account eight, non empty root but wrong slots in the end
			helper.makeCurrStorageTrie(hashData([]byte("acc-8")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-8", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-8", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "badval-3"})

			// Account 9, non empty root but rotated slots
			helper.makeCurrStorageTrie(hashData([]byte("acc-9")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-9", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-9", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-3", "val-2"})
		}

		// Extra storage slots
		{
			// Account 10, non empty root but extra slots in the beginning
			helper.makeCurrStorageTrie(hashData([]byte("acc-10")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-10", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-10", []string{"key-0", "key-1", "key-2", "key-3"}, []string{"val-0", "val-1", "val-2", "val-3"})

			// Account 11, non empty root but extra slots in the middle
			helper.makeCurrStorageTrie(hashData([]byte("acc-11")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-11", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-11", []string{"key-1", "key-2", "key-2-1", "key-3"}, []string{"val-1", "val-2", "val-2-1", "val-3"})

			// Account 12, non empty root but extra slots in the end
			helper.makeCurrStorageTrie(hashData([]byte("acc-12")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
			helper.addCurrAccount("acc-12", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addSnapStorage("acc-12", []string{"key-1", "key-2", "key-3", "key-4"}, []string{"val-1", "val-2", "val-3", "val-4"})
		}
	}

	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	t.Logf("Root: %#x\n", root) // Root = 0x28b66cce6e37ef937941f9e5a81f071fda21c00df940870762e48b5911a33f05

	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation with existent flat state, where the flat state
// contains some errors:
// - miss accounts
// - wrong accounts
// - extra accounts
func TestGenerateExistentStateWithWrongAccounts(t *testing.T) {
	testGenerateExistentStateWithWrongAccounts(t, rawdb.HashScheme)
	testGenerateExistentStateWithWrongAccounts(t, rawdb.PathScheme)
}

func testGenerateExistentStateWithWrongAccounts(t *testing.T, scheme string) {
	helper := newHelper(10, scheme)
	// checkpoint state
	{
		helper.makeCkptStorageTrie(hashData([]byte("acc-1-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		helper.makeCkptStorageTrie(hashData([]byte("acc-2-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		helper.makeCkptStorageTrie(hashData([]byte("acc-3-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		helper.makeCkptStorageTrie(hashData([]byte("acc-4-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		stRoot := helper.makeCkptStorageTrie(hashData([]byte("acc-6-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)

		// Trie accounts [acc-1, acc-2, acc-3, acc-4, acc-6]
		// Extra accounts [acc-0, acc-5, acc-7]

		// Missing accounts, only in the trie
		{
			helper.addCkptTrieAccount("acc-1-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // Beginning
			helper.addCkptTrieAccount("acc-4-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // Middle
			helper.addCkptTrieAccount("acc-6-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // End
		}

		// Wrong accounts
		{
			helper.addCkptTrieAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addCkptSnapAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: common.Hex2Bytes("0x1234")})

			helper.addCkptTrieAccount("acc-3-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addCkptSnapAccount("acc-3-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		}

		// Extra accounts, only in the snap
		{
			helper.addCkptSnapAccount("acc-0-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // before the beginning
			helper.addCkptSnapAccount("acc-5-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: common.Hex2Bytes("0x1234")})                                       // Middle
			helper.addCkptSnapAccount("acc-7-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // after the end
		}
	}
	// current state
	{
		helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.makeCurrStorageTrie(hashData([]byte("acc-2")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.makeCurrStorageTrie(hashData([]byte("acc-4")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-6")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)

		// Trie accounts [acc-1, acc-2, acc-3, acc-4, acc-6]
		// Extra accounts [acc-0, acc-5, acc-7]

		// Missing accounts, only in the trie
		{
			helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // Beginning
			helper.addCurrTrieAccount("acc-4", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // Middle
			helper.addCurrTrieAccount("acc-6", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // End
		}

		// Wrong accounts
		{
			helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addCurrSnapAccount("acc-2", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: common.Hex2Bytes("0x1234")})

			helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
			helper.addCurrSnapAccount("acc-3", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		}

		// Extra accounts, only in the snap
		{
			helper.addCurrSnapAccount("acc-0", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // before the beginning
			helper.addCurrSnapAccount("acc-5", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: common.Hex2Bytes("0x1234")})                                       // Middle
			helper.addCurrSnapAccount("acc-7", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // after the end
		}
	}

	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	t.Logf("Root: %#x\n", root) // Root = 0xbd84c1708ef8cc41657984e4f0eb05f5b95a5500d868e935e23a9f8fe89fade3

	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)

	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation errors out correctly in case of a missing trie
// node in the account trie.
func TestGenerateCorruptAccountTrie(t *testing.T) {
	testGenerateCorruptAccountTrie(t, rawdb.HashScheme)
	testGenerateCorruptAccountTrie(t, rawdb.PathScheme)
}

func testGenerateCorruptAccountTrie(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// without any storage slots to keep the test smaller.
	helper := newHelper(0, scheme)

	helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x77364da24ee1b5509b40d8ca08a7429b05a566d1db17c30b65cda2b2734d7af2
	helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2
	helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x11039c1d417a72f1b2d04e7b951fbbb0259f98c66d56452fad5a64e99d2c08e9

	root, ckptRoot := helper.Commit() // Root: 0xf21b87d9ccdfcd4524b9c2d4eb6afeed44128499debe2fe04ddb0504ecbc4303

	// Delete an account trie node and ensure the generator chokes
	targetPath := []byte{0xc}
	targetHash := common.HexToHash("0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2")

	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch, common.Hash{}, targetPath, targetHash, scheme)

	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt account trie")

	case <-time.After(time.Second):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

func TestGenerateCorruptCkptAccountTrie(t *testing.T) {
	testGenerateCorruptCkptAccountTrie(t, rawdb.HashScheme)
	testGenerateCorruptCkptAccountTrie(t, rawdb.PathScheme)
}

func testGenerateCorruptCkptAccountTrie(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// without any storage slots to keep the test smaller.
	helper := newHelper(10, scheme)
	// Checkpoint State
	{
		helper.addCkptTrieAccount("acc-1-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x501cddcf0a0617044e03bed88e4ede5c67bf2e4eb4ca8fb3ae1c56ce016be26a
		helper.addCkptTrieAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x621d42be7a39485047a36cecb8eda8eeb784a403ba1ba5f67ea433b3cb81a285
		helper.addCkptTrieAccount("acc-3-ckpt", &types.StateAccount{Balance: big.NewInt(3), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0xdc67dfa90353bdd4771b3d0e025e8ffeede4ed6923cdd34c28b40dffcf2ef50f
	}
	// Current State
	{
		helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x77364da24ee1b5509b40d8ca08a7429b05a566d1db17c30b65cda2b2734d7af2
		helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2
		helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x11039c1d417a72f1b2d04e7b951fbbb0259f98c66d56452fad5a64e99d2c08e9
	}

	root, ckptRoot := helper.Commit() // Root: 0x585dc07cf325c1ee738d5f7d9423dc7d78082cf15a7ec8c70846daa138e6d3e5

	// Delete an account trie node and ensure the generator chokes
	targetPath := []byte{0x2, 0x7}
	targetHash := common.HexToHash("0x621d42be7a39485047a36cecb8eda8eeb784a403ba1ba5f67ea433b3cb81a285")

	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch-1, common.Hash{}, targetPath, targetHash, scheme)

	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt account trie")

	case <-time.After(time.Second):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation errors out correctly in case of a missing root
// trie node for a storage trie. It's similar to internal corruption but it is
// handled differently inside the generator.
func TestGenerateMissingStorageTrie(t *testing.T) {
	testGenerateMissingStorageTrie(t, rawdb.HashScheme)
	testGenerateMissingStorageTrie(t, rawdb.PathScheme)
}

func testGenerateMissingStorageTrie(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// two of which also has the same 3-slot storage trie attached.
	var (
		acc1   = hashData([]byte("acc-1"))
		acc3   = hashData([]byte("acc-3"))
		helper = newHelper(0, scheme)
	)
	stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)                                        // 0xddefcd9376dd029653ef384bd2f0a126bb755fe84fdcc9e7cf421ba454f2bc67
	helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // 0x2abd3f77bb9e986036589c47959aba02b5d5d108218291fd5d8ef2e79a4042db
	helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2
	stRoot = helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x4d004682007519340a92e74d49faf03a26076fdd857bdc3e55a367746946b267

	root, ckptRoot := helper.Commit()

	// Delete storage trie root of account one and three.
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch, acc1, nil, stRoot, scheme)
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch, acc3, nil, stRoot, scheme)

	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt storage trie")

	case <-time.After(time.Second):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

func TestGenerateMissingCkptStorageTrie(t *testing.T) {
	testGenerateMissingCkptStorageTrie(t, rawdb.HashScheme)
	testGenerateMissingCkptStorageTrie(t, rawdb.PathScheme)
}

func testGenerateMissingCkptStorageTrie(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// two of which also has the same 3-slot storage trie attached.
	var (
		acc1       = hashData([]byte("acc-1-ckpt"))
		acc3       = hashData([]byte("acc-3-ckpt"))
		helper     = newHelper(10, scheme)
		ckptStRoot common.Hash
	)
	// Checkpoint State
	{
		ckptStRoot = helper.makeCkptStorageTrie(hashData([]byte("acc-1-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)       // 0x0629ee0735a2ac395f53e4260cdc1d01f0466786c94016d1330ab3926695fe79
		helper.addCkptTrieAccount("acc-1-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})          // 0x36fbff893c3e639e2d7559d0629833b36d9b636b02b9273d52d38243b74a0fff
		helper.addCkptTrieAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x04b309460361a606099c64fb351c6de08c7bfbf4c44b7090f53d7f5e722833b5
		ckptStRoot = helper.makeCkptStorageTrie(hashData([]byte("acc-3-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		helper.addCkptTrieAccount("acc-3-ckpt", &types.StateAccount{Balance: big.NewInt(3), Root: ckptStRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x594f57994d96370e7d34e762a75fcabbc3cb6bb2c87e3bec3144f6576f21b6ae
	}
	// Current State
	{
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)                                        // 0xddefcd9376dd029653ef384bd2f0a126bb755fe84fdcc9e7cf421ba454f2bc67
		helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // 0x2abd3f77bb9e986036589c47959aba02b5d5d108218291fd5d8ef2e79a4042db
		helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2
		stRoot = helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x4d004682007519340a92e74d49faf03a26076fdd857bdc3e55a367746946b267
	}
	root, ckptRoot := helper.Commit()

	// Delete storage trie root of account one and three.
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch-1, acc1, nil, ckptStRoot, scheme)
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch-1, acc3, nil, ckptStRoot, scheme)

	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt storage trie")

	case <-time.After(time.Second):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation errors out correctly in case of a missing trie
// node in a storage trie.
func TestGenerateCorruptStorageTrie(t *testing.T) {
	testGenerateCorruptStorageTrie(t, rawdb.HashScheme)
	testGenerateCorruptStorageTrie(t, rawdb.PathScheme)
}

func testGenerateCorruptStorageTrie(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// two of which also has the same 3-slot storage trie attached.
	helper := newHelper(0, scheme)

	stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)                                        // 0xddefcd9376dd029653ef384bd2f0a126bb755fe84fdcc9e7cf421ba454f2bc67
	helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // 0x2abd3f77bb9e986036589c47959aba02b5d5d108218291fd5d8ef2e79a4042db
	helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2
	stRoot = helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x4d004682007519340a92e74d49faf03a26076fdd857bdc3e55a367746946b267

	root, ckptRoot := helper.Commit()

	// Delete a node in the storage trie.
	targetPath := []byte{0x4}
	targetHash := common.HexToHash("0x18a0f4d79cff4459642dd7604f303886ad9d77c30cf3d7d7cedb3a693ab6d371")
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch, hashData([]byte("acc-1")), targetPath, targetHash, scheme)
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch, hashData([]byte("acc-3")), targetPath, targetHash, scheme)

	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt storage trie")

	case <-time.After(time.Second):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

func TestGenerateCorruptCkptStorageTrie(t *testing.T) {
	testGenerateCorruptCkptStorageTrie(t, rawdb.HashScheme)
	testGenerateCorruptCkptStorageTrie(t, rawdb.PathScheme)
}

func testGenerateCorruptCkptStorageTrie(t *testing.T, scheme string) {
	// We can't use statedb to make a test trie (circular dependency), so make
	// a fake one manually. We're going with a small account trie of 3 accounts,
	// two of which also has the same 3-slot storage trie attached.
	helper := newHelper(10, scheme)
	// Checkpoint State
	{
		stRoot := helper.makeCkptStorageTrie(hashData([]byte("acc-1-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)          // 0x0629ee0735a2ac395f53e4260cdc1d01f0466786c94016d1330ab3926695fe79
		helper.addCkptTrieAccount("acc-1-ckpt", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // 0x04b309460361a606099c64fb351c6de08c7bfbf4c44b7090f53d7f5e722833b5
		helper.addCkptTrieAccount("acc-2-ckpt", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0xdc67dfa90353bdd4771b3d0e025e8ffeede4ed6923cdd34c28b40dffcf2ef50f
		stRoot = helper.makeCkptStorageTrie(hashData([]byte("acc-3-ckpt")), []string{"key-1-ckpt", "key-2-ckpt", "key-3-ckpt"}, []string{"val-1-ckpt", "val-2-ckpt", "val-3-ckpt"}, true)
		helper.addCkptTrieAccount("acc-3-ckpt", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0xca3372644178f2ceaf20f4ad39fc009f1541b3276d7b2a7d3a87e5465db0d667
	}
	// Current State
	{
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)                                        // 0xddefcd9376dd029653ef384bd2f0a126bb755fe84fdcc9e7cf421ba454f2bc67
		helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})              // 0x2abd3f77bb9e986036589c47959aba02b5d5d108218291fd5d8ef2e79a4042db
		helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x3bea89fb1c1f6b9240e0b49de35e56c2401ca0aec7b8d8e5fb8cca7886a2f5b2
		stRoot = helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}) // 0x4d004682007519340a92e74d49faf03a26076fdd857bdc3e55a367746946b267
	}

	root, ckptRoot := helper.Commit()

	// Delete a node in the storage trie.
	targetPath := []byte{0xc}
	targetHash := common.HexToHash("0x200c1e6e48296b18a0eb8615984aeb7def9bb1a765dc8f7324258eaff982222b")
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch-1, hashData([]byte("acc-1-ckpt")), targetPath, targetHash, scheme)
	rawdb.DeleteTrieNode(helper.diskdb, helper.epoch-1, hashData([]byte("acc-3-ckpt")), targetPath, targetHash, scheme)

	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded
		t.Errorf("Snapshot generated against corrupt storage trie")

	case <-time.After(time.Second):
		// Not generated fast enough, hopefully blocked inside on missing trie node fail
	}
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation when an extra account with storage exists in the snap state.
func TestGenerateWithExtraAccounts(t *testing.T) {
	testGenerateWithExtraAccounts(t, rawdb.HashScheme)
	testGenerateWithExtraAccounts(t, rawdb.PathScheme)
}

func testGenerateWithExtraAccounts(t *testing.T, scheme string) {
	helper := newHelper(0, scheme)
	{
		// Account one in the trie
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")),
			[]string{"key-1", "key-2", "key-3", "key-4", "key-5"},
			[]string{"val-1", "val-2", "val-3", "val-4", "val-5"},
			true,
		)
		acc := &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}
		val, _ := rlp.EncodeToBytes(acc)
		helper.accTrie.MustUpdate([]byte("acc-1"), val) // 0x2abd3f77bb9e986036589c47959aba02b5d5d108218291fd5d8ef2e79a4042db

		// Identical in the snap
		key := hashData([]byte("acc-1"))
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, key, val)
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-1")), []byte("val-1"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-2")), []byte("val-2"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-3")), []byte("val-3"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-4")), []byte("val-4"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-5")), []byte("val-5"))
	}
	{
		// Account two exists only in the snapshot
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-2")),
			[]string{"key-1", "key-2", "key-3", "key-4", "key-5"},
			[]string{"val-1", "val-2", "val-3", "val-4", "val-5"},
			true,
		)
		acc := &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}
		val, _ := rlp.EncodeToBytes(acc)
		key := hashData([]byte("acc-2"))
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, key, val)
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("b-key-1")), []byte("b-val-1"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("b-key-2")), []byte("b-val-2"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("b-key-3")), []byte("b-val-3"))
	}
	root, ckptRoot := helper.Commit()

	// To verify the test: If we now inspect the snap db, there should exist extraneous storage items
	if data := rawdb.ReadStorageSnapshot(helper.diskdb, hashData([]byte("acc-2")), hashData([]byte("b-key-1"))); data == nil {
		t.Fatalf("expected snap storage to exist")
	}
	snap := generateSnapshot(helper.diskdb, helper.triedb, 16, helper.epoch, root, ckptRoot, nil)
	ckptSnap := snap.ckptLayer
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)

	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
	// If we now inspect the snap db, there should exist no extraneous storage items
	if data := rawdb.ReadStorageSnapshot(helper.diskdb, hashData([]byte("acc-2")), hashData([]byte("b-key-1"))); data != nil {
		t.Fatalf("expected slot to be removed, got %v", string(data))
	}
}

func enableLogging() {
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelTrace, true)))
}

// Tests that snapshot generation when an extra account with storage exists in the snap state.
func TestGenerateWithManyExtraAccounts(t *testing.T) {
	testGenerateWithManyExtraAccounts(t, rawdb.HashScheme)
	testGenerateWithManyExtraAccounts(t, rawdb.PathScheme)
}

func testGenerateWithManyExtraAccounts(t *testing.T, scheme string) {
	if false {
		enableLogging()
	}
	helper := newHelper(0, scheme)
	{
		// Account one in the trie
		stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")),
			[]string{"key-1", "key-2", "key-3"},
			[]string{"val-1", "val-2", "val-3"},
			true,
		)
		acc := &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}
		val, _ := rlp.EncodeToBytes(acc)
		helper.accTrie.MustUpdate([]byte("acc-1"), val) // 0x2abd3f77bb9e986036589c47959aba02b5d5d108218291fd5d8ef2e79a4042db

		// Identical in the snap
		key := hashData([]byte("acc-1"))
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, key, val)
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-1")), []byte("val-1"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-2")), []byte("val-2"))
		rawdb.WriteStorageSnapshot(helper.diskdb, key, hashData([]byte("key-3")), []byte("val-3"))
	}
	{
		// 100 accounts exist only in snapshot
		for i := 0; i < 1000; i++ {
			acc := &types.StateAccount{Balance: big.NewInt(int64(i)), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}
			val, _ := rlp.EncodeToBytes(acc)
			key := hashData([]byte(fmt.Sprintf("acc-%d", i)))
			rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, key, val)
		}
	}
	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests this case
// maxAccountRange 3
// snapshot-accounts: 01, 02, 03, 04, 05, 06, 07
// trie-accounts:             03,             07
//
// We iterate three snapshot storage slots (max = 3) from the database. They are 0x01, 0x02, 0x03.
// The trie has a lot of deletions.
// So in trie, we iterate 2 entries 0x03, 0x07. We create the 0x07 in the database and abort the procedure, because the trie is exhausted.
// But in the database, we still have the stale storage slots 0x04, 0x05. They are not iterated yet, but the procedure is finished.
func TestGenerateWithExtraBeforeAndAfter(t *testing.T) {
	testGenerateWithExtraBeforeAndAfter(t, rawdb.HashScheme)
	testGenerateWithExtraBeforeAndAfter(t, rawdb.PathScheme)
}

func testGenerateWithExtraBeforeAndAfter(t *testing.T, scheme string) {
	accountCheckRange = 3
	if false {
		enableLogging()
	}
	helper := newHelper(0, scheme)
	{
		acc := &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}
		val, _ := rlp.EncodeToBytes(acc)
		helper.accTrie.MustUpdate(common.HexToHash("0x03").Bytes(), val)
		helper.accTrie.MustUpdate(common.HexToHash("0x07").Bytes(), val)

		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x01"), val)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x02"), val)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x03"), val)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x04"), val)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x05"), val)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x06"), val)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x07"), val)
	}
	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// TestGenerateWithMalformedSnapdata tests what happes if we have some junk
// in the snapshot database, which cannot be parsed back to an account
func TestGenerateWithMalformedSnapdata(t *testing.T) {
	testGenerateWithMalformedSnapdata(t, rawdb.HashScheme)
	testGenerateWithMalformedSnapdata(t, rawdb.PathScheme)
}

func testGenerateWithMalformedSnapdata(t *testing.T, scheme string) {
	accountCheckRange = 3
	if false {
		enableLogging()
	}
	helper := newHelper(0, scheme)
	{
		acc := &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()}
		val, _ := rlp.EncodeToBytes(acc)
		helper.accTrie.MustUpdate(common.HexToHash("0x03").Bytes(), val)

		junk := make([]byte, 100)
		copy(junk, []byte{0xde, 0xad})
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x02"), junk)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x03"), junk)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x04"), junk)
		rawdb.WriteAccountSnapshot(helper.diskdb, helper.epoch, common.HexToHash("0x05"), junk)
	}
	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
	// If we now inspect the snap db, there should exist no extraneous storage items
	if data := rawdb.ReadStorageSnapshot(helper.diskdb, hashData([]byte("acc-2")), hashData([]byte("b-key-1"))); data != nil {
		t.Fatalf("expected slot to be removed, got %v", string(data))
	}
}

func TestGenerateFromEmptySnap(t *testing.T) {
	testGenerateFromEmptySnap(t, rawdb.HashScheme)
	testGenerateFromEmptySnap(t, rawdb.PathScheme)
}

func testGenerateFromEmptySnap(t *testing.T, scheme string) {
	//enableLogging()
	accountCheckRange = 10
	storageCheckRange = 20
	helper := newHelper(0, scheme)
	// Add 1K accounts to the trie
	for i := 0; i < 400; i++ {
		stRoot := helper.makeCurrStorageTrie(hashData([]byte(fmt.Sprintf("acc-%d", i))), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
		helper.addCurrTrieAccount(fmt.Sprintf("acc-%d", i),
			&types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
	}
	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	t.Logf("Root: %#x\n", root) // Root: 0x6f7af6d2e1a1bf2b84a3beb3f8b64388465fbc1e274ca5d5d3fc787ca78f59e4

	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation with existent flat state, where the flat state
// storage is correct, but incomplete.
// The incomplete part is on the second range
// snap: [ 0x01, 0x02, 0x03, 0x04] , [ 0x05, 0x06, 0x07, {missing}] (with storageCheck = 4)
// trie:  0x01, 0x02, 0x03, 0x04,  0x05, 0x06, 0x07, 0x08
// This hits a case where the snap verification passes, but there are more elements in the trie
// which we must also add.
func TestGenerateWithIncompleteStorage(t *testing.T) {
	testGenerateWithIncompleteStorage(t, rawdb.HashScheme)
	testGenerateWithIncompleteStorage(t, rawdb.PathScheme)
}

func testGenerateWithIncompleteStorage(t *testing.T, scheme string) {
	storageCheckRange = 4
	helper := newHelper(0, scheme)
	stKeys := []string{"1", "2", "3", "4", "5", "6", "7", "8"}
	stVals := []string{"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"}
	// We add 8 accounts, each one is missing exactly one of the storage slots. This means
	// we don't have to order the keys and figure out exactly which hash-key winds up
	// on the sensitive spots at the boundaries
	for i := 0; i < 8; i++ {
		accKey := fmt.Sprintf("acc-%d", i)
		stRoot := helper.makeCurrStorageTrie(hashData([]byte(accKey)), stKeys, stVals, true)
		helper.addCurrAccount(accKey, &types.StateAccount{Balance: big.NewInt(int64(i)), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
		var moddedKeys []string
		var moddedVals []string
		for ii := 0; ii < 8; ii++ {
			if ii != i {
				moddedKeys = append(moddedKeys, stKeys[ii])
				moddedVals = append(moddedVals, stVals[ii])
			}
		}
		helper.addSnapStorage(accKey, moddedKeys, moddedVals)
	}
	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	t.Logf("Root: %#x\n", root) // Root: 0xca73f6f05ba4ca3024ef340ef3dfca8fdabc1b677ff13f5a9571fd49c16e67ff

	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)
	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

func incKey(key []byte) []byte {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]++
		if key[i] != 0x0 {
			break
		}
	}
	return key
}

func decKey(key []byte) []byte {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]--
		if key[i] != 0xff {
			break
		}
	}
	return key
}

func populateDangling(disk ethdb.KeyValueStore) {
	populate := func(accountHash common.Hash, keys []string, vals []string) {
		for i, key := range keys {
			rawdb.WriteStorageSnapshot(disk, accountHash, hashData([]byte(key)), []byte(vals[i]))
		}
	}
	// Dangling storages of the "first" account
	populate(common.Hash{}, []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

	// Dangling storages of the "last" account
	populate(common.HexToHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

	// Dangling storages around the account 1
	hash := decKey(hashData([]byte("acc-1")).Bytes())
	populate(common.BytesToHash(hash), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	hash = incKey(hashData([]byte("acc-1")).Bytes())
	populate(common.BytesToHash(hash), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

	// Dangling storages around the account 2
	hash = decKey(hashData([]byte("acc-2")).Bytes())
	populate(common.BytesToHash(hash), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	hash = incKey(hashData([]byte("acc-2")).Bytes())
	populate(common.BytesToHash(hash), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

	// Dangling storages around the account 3
	hash = decKey(hashData([]byte("acc-3")).Bytes())
	populate(common.BytesToHash(hash), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	hash = incKey(hashData([]byte("acc-3")).Bytes())
	populate(common.BytesToHash(hash), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

	// Dangling storages of the random account
	populate(randomHash(), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	populate(randomHash(), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	populate(randomHash(), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
}

// Tests that snapshot generation with dangling storages. Dangling storage means
// the storage data is existent while the corresponding account data is missing.
//
// This test will populate some dangling storages to see if they can be cleaned up.
func TestGenerateCompleteSnapshotWithDanglingStorage(t *testing.T) {
	testGenerateCompleteSnapshotWithDanglingStorage(t, rawdb.HashScheme)
	testGenerateCompleteSnapshotWithDanglingStorage(t, rawdb.PathScheme)
}

func testGenerateCompleteSnapshotWithDanglingStorage(t *testing.T, scheme string) {
	var helper = newHelper(0, scheme)

	stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	helper.addCurrAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
	helper.addCurrAccount("acc-2", &types.StateAccount{Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

	helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	helper.addCurrAccount("acc-3", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

	helper.addSnapStorage("acc-1", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})
	helper.addSnapStorage("acc-3", []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"})

	populateDangling(helper.diskdb)

	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)

	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}

// Tests that snapshot generation with dangling storages. Dangling storage means
// the storage data is existent while the corresponding account data is missing.
//
// This test will populate some dangling storages to see if they can be cleaned up.
func TestGenerateBrokenSnapshotWithDanglingStorage(t *testing.T) {
	testGenerateBrokenSnapshotWithDanglingStorage(t, rawdb.HashScheme)
	testGenerateBrokenSnapshotWithDanglingStorage(t, rawdb.PathScheme)
}

func testGenerateBrokenSnapshotWithDanglingStorage(t *testing.T, scheme string) {
	var helper = newHelper(0, scheme)

	stRoot := helper.makeCurrStorageTrie(hashData([]byte("acc-1")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	helper.addCurrTrieAccount("acc-1", &types.StateAccount{Balance: big.NewInt(1), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})
	helper.addCurrTrieAccount("acc-2", &types.StateAccount{Balance: big.NewInt(2), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

	helper.makeCurrStorageTrie(hashData([]byte("acc-3")), []string{"key-1", "key-2", "key-3"}, []string{"val-1", "val-2", "val-3"}, true)
	helper.addCurrTrieAccount("acc-3", &types.StateAccount{Balance: big.NewInt(3), Root: stRoot, CodeHash: types.EmptyCodeHash.Bytes(), UiHash: types.EmptyRootHash.Bytes()})

	populateDangling(helper.diskdb)

	root, ckptRoot, snap, ckptSnap := helper.CommitAndGenerate()
	select {
	case <-snap.genPending:
		// Snapshot generation succeeded

	case <-time.After(3 * time.Second):
		t.Errorf("Snapshot generation failed")
	}
	checkSnapRoot(t, helper.epoch, snap, ckptSnap, root, ckptRoot)

	// Signal abortion to the generator and wait for it to tear down
	stop := make(chan *generatorStats)
	snap.genAbort <- stop
	<-stop
}
