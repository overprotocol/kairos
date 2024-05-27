// Copyright 2014 The go-ethereum Authors
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

package state

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
)

type stateEnv struct {
	db    ethdb.Database
	state *StateDB
}

func newStateEnv(epoch uint32, config *trie.Config) *stateEnv {
	db := rawdb.NewMemoryDatabase()
	tdb := NewDatabaseWithConfig(db, config)
	sdb, _ := New(types.EmptyRootHash, types.EmptyRootHash, epoch, 0, tdb, nil)
	return &stateEnv{db: db, state: sdb}
}

func TestDump(t *testing.T) {
	s := newStateEnv(27, &trie.Config{Preimages: true})

	// generate a few entries
	obj1 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x01}))
	obj1.AddBalance(big.NewInt(22))
	obj2 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x01, 0x02}))
	obj2.SetCode(crypto.Keccak256Hash([]byte{3, 3, 3, 3, 3, 3, 3}), []byte{3, 3, 3, 3, 3, 3, 3})
	obj3 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x02}))
	obj3.SetBalance(big.NewInt(44))
	obj4 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x03}))
	obj4.setEpochCoverage(30)

	// write some of them to the trie
	s.state.updateStateObject(obj1)
	s.state.updateStateObject(obj2)
	root, _ := s.state.Commit(0, false)

	// check that DumpToCollector contains the state objects that are in trie
	s.state, _ = New(root, types.EmptyRootHash, 0, 0, s.state.db, nil)
	got := string(s.state.Dump(nil))
	want := `{
    "root": "9952e69d7ae924bcd8128c649053f25b197ac58631edbaeac69e6ed667691607",
    "accounts": {
        "0x0000000000000000000000000000000000000001": {
            "balance": "22",
            "nonce": 0,
            "epochCoverage": 26,
            "root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "uiHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "address": "0x0000000000000000000000000000000000000001",
            "key": "0x1468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d"
        },
        "0x0000000000000000000000000000000000000002": {
            "balance": "44",
            "nonce": 0,
            "epochCoverage": 26,
            "root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "uiHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "address": "0x0000000000000000000000000000000000000002",
            "key": "0xd52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62"
        },
        "0x0000000000000000000000000000000000000003": {
            "balance": "0",
            "nonce": 0,
            "epochCoverage": 30,
            "root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "uiHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "address": "0x0000000000000000000000000000000000000003",
            "key": "0x5b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b9"
        },
        "0x0000000000000000000000000000000000000102": {
            "balance": "0",
            "nonce": 0,
            "epochCoverage": 26,
            "root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "codeHash": "0x87874902497a5bb968da31a2998d8f22e949d1ef6214bcdedd8bae24cca4b9e3",
            "code": "0x03030303030303",
            "uiHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "address": "0x0000000000000000000000000000000000000102",
            "key": "0xa17eacbc25cda025e81db9c5c62868822c73ce097cee2a63e33a2e41268358a1"
        }
    }
}`
	if got != want {
		t.Errorf("DumpToCollector mismatch:\ngot: %s\nwant: %s\n", got, want)
	}
}

func TestIterativeDump(t *testing.T) {
	s := newStateEnv(26, &trie.Config{Preimages: true})

	// generate a few entries
	obj1 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x01}))
	obj1.AddBalance(big.NewInt(22))
	obj2 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x01, 0x02}))
	obj2.SetCode(crypto.Keccak256Hash([]byte{3, 3, 3, 3, 3, 3, 3}), []byte{3, 3, 3, 3, 3, 3, 3})
	obj3 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x02}))
	obj3.SetBalance(big.NewInt(44))
	obj4 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x00}))
	obj4.AddBalance(big.NewInt(1337))
	obj5 := s.state.GetOrNewStateObject(common.BytesToAddress([]byte{0x03}))
	obj5.setEpochCoverage(30)

	// write some of them to the trie
	s.state.updateStateObject(obj1)
	s.state.updateStateObject(obj2)
	root, _ := s.state.Commit(0, false)
	s.state, _ = New(root, types.EmptyRootHash, 0, 0, s.state.db, nil)

	b := &bytes.Buffer{}
	s.state.IterativeDump(nil, json.NewEncoder(b))
	// check that DumpToCollector contains the state objects that are in trie
	got := b.String()
	want := `{"root":"0x5a84e1d2b1f0959c92b67fd08009ff0348abe4611c8c0719099388b303fe9cf9"}
{"balance":"22","nonce":0,"epochCoverage":25,"root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","codeHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","uiHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","address":"0x0000000000000000000000000000000000000001","key":"0x1468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d"}
{"balance":"1337","nonce":0,"epochCoverage":25,"root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","codeHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","uiHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","address":"0x0000000000000000000000000000000000000000","key":"0x5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a"}
{"balance":"0","nonce":0,"epochCoverage":30,"root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","codeHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","uiHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","address":"0x0000000000000000000000000000000000000003","key":"0x5b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b9"}
{"balance":"0","nonce":0,"epochCoverage":25,"root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","codeHash":"0x87874902497a5bb968da31a2998d8f22e949d1ef6214bcdedd8bae24cca4b9e3","code":"0x03030303030303","uiHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","address":"0x0000000000000000000000000000000000000102","key":"0xa17eacbc25cda025e81db9c5c62868822c73ce097cee2a63e33a2e41268358a1"}
{"balance":"44","nonce":0,"epochCoverage":25,"root":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","codeHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","uiHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","address":"0x0000000000000000000000000000000000000002","key":"0xd52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62"}
`
	if got != want {
		t.Errorf("DumpToCollector mismatch:\ngot: %s\nwant: %s\n", got, want)
	}
}

func TestNull(t *testing.T) {
	s := newStateEnv(27, nil)
	address := common.HexToAddress("0x823140710bf13990e4500136726d8b55")
	s.state.CreateAccount(address)
	//value := common.FromHex("0x823140710bf13990e4500136726d8b55")
	var value common.Hash

	s.state.SetState(address, common.Hash{}, value)
	s.state.Commit(0, false)

	if value := s.state.GetState(address, common.Hash{}); value != (common.Hash{}) {
		t.Errorf("expected empty current value, got %x", value)
	}
	if value := s.state.GetCommittedState(address, common.Hash{}); value != (common.Hash{}) {
		t.Errorf("expected empty committed value, got %x", value)
	}
}

func TestStorageCount(t *testing.T) {
	s := newStateEnv(30, nil)
	stateobjaddr := common.BytesToAddress([]byte("aa"))
	key1 := common.BytesToHash([]byte("key-1"))
	value1 := common.BytesToHash([]byte("value-1"))
	key2 := common.BytesToHash([]byte("key-2"))
	value2 := common.BytesToHash([]byte("value-2"))
	value1Update := common.BytesToHash([]byte("value-1-update"))
	key3 := common.BytesToHash([]byte("key-3"))
	emptyValue := common.Hash{}

	// Add non-empty value
	s.state.SetState(stateobjaddr, key1, value1)
	if v := s.state.GetStorageCount(stateobjaddr); v != 1 {
		t.Errorf("wrong storage count %v, want %v", v, 1)
	}
	// Add another non-empty value
	s.state.SetState(stateobjaddr, key2, value2)
	if v := s.state.GetStorageCount(stateobjaddr); v != 2 {
		t.Errorf("wrong storage count %v, want %v", v, 2)
	}
	// Update non-empty value with non-empty value
	s.state.SetState(stateobjaddr, key1, value1Update)
	if v := s.state.GetStorageCount(stateobjaddr); v != 2 {
		t.Errorf("wrong storage count %v, want %v", v, 2)
	}
	// Update non-empty value with empty value
	s.state.SetState(stateobjaddr, key2, emptyValue)
	if v := s.state.GetStorageCount(stateobjaddr); v != 1 {
		t.Errorf("wrong storage count %v, want %v", v, 1)
	}
	// Update empty value with empty value
	s.state.SetState(stateobjaddr, key2, emptyValue)
	if v := s.state.GetStorageCount(stateobjaddr); v != 1 {
		t.Errorf("wrong storage count %v, want %v", v, 1)
	}
	// Update non-empty value with empty value
	s.state.SetState(stateobjaddr, key1, emptyValue)
	if v := s.state.GetStorageCount(stateobjaddr); v != 0 {
		t.Errorf("wrong storage count %v, want %v", v, 0)
	}
	// Update empty value with empty value
	s.state.SetState(stateobjaddr, key3, emptyValue)
	if v := s.state.GetStorageCount(stateobjaddr); v != 0 {
		t.Errorf("wrong storage count %v, want %v", v, 0)
	}
}

func TestSnapshot(t *testing.T) {
	stateobjaddr := common.BytesToAddress([]byte("aa"))
	var storageaddr common.Hash
	data1 := common.BytesToHash([]byte{42})
	data2 := common.BytesToHash([]byte{43})
	s := newStateEnv(30, nil)

	// snapshot the genesis state
	genesis := s.state.Snapshot()

	// set initial state object value
	s.state.SetState(stateobjaddr, storageaddr, data1)
	snapshot := s.state.Snapshot()

	// set a new state object value, revert it and ensure correct content
	s.state.SetState(stateobjaddr, storageaddr, data2)
	s.state.RevertToSnapshot(snapshot)

	if v := s.state.GetEpochCoverage(stateobjaddr); v != 29 {
		t.Errorf("wrong epochCoverage value %v, want %v", v, 29)
	}
	if v := s.state.GetState(stateobjaddr, storageaddr); v != data1 {
		t.Errorf("wrong storage value %v, want %v", v, data1)
	}
	if v := s.state.GetCommittedState(stateobjaddr, storageaddr); v != (common.Hash{}) {
		t.Errorf("wrong committed storage value %v, want %v", v, common.Hash{})
	}

	// revert up to the genesis state and ensure correct content
	s.state.RevertToSnapshot(genesis)
	if v := s.state.GetState(stateobjaddr, storageaddr); v != (common.Hash{}) {
		t.Errorf("wrong storage value %v, want %v", v, common.Hash{})
	}
	if v := s.state.GetCommittedState(stateobjaddr, storageaddr); v != (common.Hash{}) {
		t.Errorf("wrong committed storage value %v, want %v", v, common.Hash{})
	}
	if v := s.state.GetStorageCount(stateobjaddr); v != 0 {
		t.Errorf("wrong storage count %v, want %v", v, 0)
	}
}

func TestSnapshotEmpty(t *testing.T) {
	s := newStateEnv(32, nil)
	s.state.RevertToSnapshot(s.state.Snapshot())
}

func TestSnapshot2(t *testing.T) {
	s := newStateEnv(31, nil)
	state := s.state

	stateobjaddr0 := common.BytesToAddress([]byte("so0"))
	stateobjaddr1 := common.BytesToAddress([]byte("so1"))
	var storageaddr common.Hash

	data0 := common.BytesToHash([]byte{17})
	data1 := common.BytesToHash([]byte{18})

	state.SetState(stateobjaddr0, storageaddr, data0)
	state.SetState(stateobjaddr1, storageaddr, data1)

	// db, trie are already non-empty values
	so0 := state.getStateObject(stateobjaddr0)
	so0.SetBalance(big.NewInt(42))
	so0.SetNonce(43)
	so0.SetCode(crypto.Keccak256Hash([]byte{'c', 'a', 'f', 'e'}), []byte{'c', 'a', 'f', 'e'})
	so0.selfDestructed = false
	so0.deleted = false
	state.setStateObject(so0)

	root, _ := state.Commit(0, false)
	state, _ = New(root, types.EmptyRootHash, 0, 0, state.db, state.snaps)

	// and one with deleted == true
	so1 := state.getStateObject(stateobjaddr1)
	so1.SetBalance(big.NewInt(52))
	so1.SetNonce(53)
	so1.SetCode(crypto.Keccak256Hash([]byte{'c', 'a', 'f', 'e', '2'}), []byte{'c', 'a', 'f', 'e', '2'})
	so1.selfDestructed = true
	so1.deleted = true
	state.setStateObject(so1)

	so1 = state.getStateObject(stateobjaddr1)
	if so1 != nil {
		t.Fatalf("deleted object not nil when getting")
	}

	snapshot := state.Snapshot()
	state.RevertToSnapshot(snapshot)

	so0Restored := state.getStateObject(stateobjaddr0)
	// Update lazily-loaded values before comparing.
	so0Restored.GetState(storageaddr)
	so0Restored.Code()
	// non-deleted is equal (restored)
	compareStateObjects(so0Restored, so0, t)

	// deleted should be nil, both before and after restore of state copy
	so1Restored := state.getStateObject(stateobjaddr1)
	if so1Restored != nil {
		t.Fatalf("deleted object not nil after restoring snapshot: %+v", so1Restored)
	}
}

func TestSnapshot3(t *testing.T) {
	stateobjaddr := common.BytesToAddress([]byte("so"))
	// initialize empty state
	s := newStateEnv(21, nil)
	state := s.state

	state.SetBalance(stateobjaddr, big.NewInt(1000))

	// commit state into database
	root, _ := state.Commit(0, false)
	if b := state.GetBalance(stateobjaddr); b.Uint64() != 1000 {
		t.Errorf("wrong balance %v, want %v", b.Uint64(), 1000)
	}

	// open the commited database as a checkpoint trie as if the state is swept
	state, _ = New(types.EmptyRootHash, root, 1, 0, state.db, nil)
	snapshot := state.Snapshot()

	if _, ok := state.stateObjects[stateobjaddr]; ok {
		t.Errorf("stateObjects must be empty")
	}
	state.AddBalance(stateobjaddr, big.NewInt(1000))

	if b := state.stateObjects[stateobjaddr].Balance(); b.Uint64() != 2000 {
		t.Errorf("wrong balance %v, want %v", b.Uint64(), 2000)
	}

	if addr := state.journal.entries[0].(loadFromCkptChange).account; *addr != stateobjaddr {
		t.Errorf("wrong address %v, want %v", *addr, stateobjaddr)
	}
	if addr := state.journal.entries[1].(balanceChange).account; *addr != stateobjaddr {
		t.Errorf("wrong address %v, want %v", *addr, stateobjaddr)
	}
	if balance := state.journal.entries[1].(balanceChange).prev; balance.Uint64() != 1000 {
		t.Errorf("wrong balance %v, want %v", balance.Uint64(), 1000)
	}

	state.RevertToSnapshot(snapshot)
	if _, ok := state.stateObjects[stateobjaddr]; ok {
		t.Errorf("stateObjects must be empty")
	}
	if journalLen := len(state.journal.entries); journalLen != 0 {
		t.Errorf("wrong journal length %v, want %v", journalLen, 0)
	}
	if balance := state.GetBalance(stateobjaddr); balance.Uint64() != 1000 {
		t.Errorf("wrong balance %v, want %v", balance.Uint64(), 1000)
	}

}

func compareStateObjects(so0, so1 *stateObject, t *testing.T) {
	if so0.Address() != so1.Address() {
		t.Fatalf("Address mismatch: have %v, want %v", so0.address, so1.address)
	}
	if so0.Balance().Cmp(so1.Balance()) != 0 {
		t.Fatalf("Balance mismatch: have %v, want %v", so0.Balance(), so1.Balance())
	}
	if so0.EpochCoverage() != so1.EpochCoverage() {
		t.Fatalf("EpochCoverage mismatch: have %v, want %v", so0.EpochCoverage(), so1.EpochCoverage())
	}
	if so0.Nonce() != so1.Nonce() {
		t.Fatalf("Nonce mismatch: have %v, want %v", so0.Nonce(), so1.Nonce())
	}
	if so0.data.Root != so1.data.Root {
		t.Errorf("Root mismatch: have %x, want %x", so0.data.Root[:], so1.data.Root[:])
	}
	if !bytes.Equal(so0.CodeHash(), so1.CodeHash()) {
		t.Fatalf("CodeHash mismatch: have %v, want %v", so0.CodeHash(), so1.CodeHash())
	}
	if !bytes.Equal(so0.code, so1.code) {
		t.Fatalf("Code mismatch: have %v, want %v", so0.code, so1.code)
	}
	if !bytes.Equal(so0.UiHash(), so1.UiHash()) {
		t.Fatalf("UiHash mismatch: have %v, want %v", so0.UiHash(), so1.UiHash())
	}

	if so0.StorageCount() != so1.StorageCount() {
		t.Fatalf("StorageCount mismatch: have %v, want %v", so0.StorageCount(), so1.StorageCount())
	}
	if len(so1.dirtyStorage) != len(so0.dirtyStorage) {
		t.Errorf("Dirty storage size mismatch: have %d, want %d", len(so1.dirtyStorage), len(so0.dirtyStorage))
	}
	for k, v := range so1.dirtyStorage {
		if so0.dirtyStorage[k] != v {
			t.Errorf("Dirty storage key %x mismatch: have %v, want %v", k, so0.dirtyStorage[k], v)
		}
	}
	for k, v := range so0.dirtyStorage {
		if so1.dirtyStorage[k] != v {
			t.Errorf("Dirty storage key %x mismatch: have %v, want none.", k, v)
		}
	}
	if len(so1.originStorage) != len(so0.originStorage) {
		t.Errorf("Origin storage size mismatch: have %d, want %d", len(so1.originStorage), len(so0.originStorage))
	}
	for k, v := range so1.originStorage {
		if so0.originStorage[k] != v {
			t.Errorf("Origin storage key %x mismatch: have %v, want %v", k, so0.originStorage[k], v)
		}
	}
	for k, v := range so0.originStorage {
		if so1.originStorage[k] != v {
			t.Errorf("Origin storage key %x mismatch: have %v, want none.", k, v)
		}
	}
}
