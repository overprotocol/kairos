// Copyright 2022 The go-ethereum Authors
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

package pathdb

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie/testutil"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/triestate"
)

var (
	BlockLength = uint32(2*128 + 30) // 2 max cap + 30 blocks (30 blocks for testing nodebuffer)
	SweepEpoch  = uint32(64)
)

func updateTrie(addrHash common.Hash, root common.Hash, dirties, cleans map[common.Hash][]byte) (common.Hash, *trienode.NodeSet) {
	h, err := newTestHasher(addrHash, root, cleans)
	if err != nil {
		panic(fmt.Errorf("failed to create hasher, err: %w", err))
	}
	for key, val := range dirties {
		if len(val) == 0 {
			h.Delete(key.Bytes())
		} else {
			h.Update(key.Bytes(), val)
		}
	}
	root, nodes, _ := h.Commit(false)
	return root, nodes
}

func generateAccount(storageRoot common.Hash) types.StateAccount {
	return types.StateAccount{
		EpochCoverage: uint32(rand.Intn(100)),
		Nonce:         uint32(rand.Intn(100)),
		Balance:       big.NewInt(rand.Int63()),
		CodeHash:      testutil.RandBytes(32),
		UiHash:        testutil.RandBytes(32),
		Root:          storageRoot,
	}
}

const (
	createAccountOp int = iota
	modifyAccountOp
	deleteAccountOp
	opLen
)

type genctx struct {
	accounts      map[common.Hash][]byte
	storages      map[common.Hash]map[common.Hash][]byte
	accountOrigin map[common.Address][]byte
	storageOrigin map[common.Address]map[common.Hash][]byte
	nodes         *trienode.MergedNodeSet
}

func newCtx() *genctx {
	return &genctx{
		accounts:      make(map[common.Hash][]byte),
		storages:      make(map[common.Hash]map[common.Hash][]byte),
		accountOrigin: make(map[common.Address][]byte),
		storageOrigin: make(map[common.Address]map[common.Hash][]byte),
		nodes:         trienode.NewMergedNodeSet(),
	}
}

type tester struct {
	db         *Database
	sweepEpoch uint32
	roots      []common.Hash
	preimages  map[common.Hash]common.Address
	accounts   map[common.Hash][]byte
	storages   map[common.Hash]map[common.Hash][]byte

	// state snapshots
	snapAccounts map[common.Hash]map[common.Hash][]byte
	snapStorages map[common.Hash]map[common.Hash]map[common.Hash][]byte
}

func newTester(t *testing.T, sweepEpoch uint32, historyLimit uint64) *tester {
	var (
		disk, _ = rawdb.NewDatabaseWithFreezer(rawdb.NewMemoryDatabase(), t.TempDir(), "", false)
		db      = New(disk, &Config{
			StateHistory:   historyLimit,
			CleanCacheSize: 256 * 1024,
			DirtyCacheSize: 256 * 1024,
		})
		obj = &tester{
			db:           db,
			sweepEpoch:   sweepEpoch,
			preimages:    make(map[common.Hash]common.Address),
			accounts:     make(map[common.Hash][]byte),
			storages:     make(map[common.Hash]map[common.Hash][]byte),
			snapAccounts: make(map[common.Hash]map[common.Hash][]byte),
			snapStorages: make(map[common.Hash]map[common.Hash]map[common.Hash][]byte),
		}
	)
	for i := 0; i < int(BlockLength); i++ {
		var parent = types.EmptyRootHash
		if len(obj.roots) != 0 {
			parent = obj.roots[len(obj.roots)-1]
		}
		sweep := i%int(sweepEpoch) == 0
		root, nodes, states := obj.generate(parent, sweep)
		if err := db.Update(root, parent, uint32(i)/sweepEpoch, uint64(i), nodes, states); err != nil {
			panic(fmt.Errorf("failed to update state changes, err: %w", err))
		}
		obj.roots = append(obj.roots, root)
	}
	return obj
}

func (t *tester) release() {
	t.db.Close()
	t.db.diskdb.Close()
}

func (t *tester) randAccount() (common.Address, []byte) {
	for addrHash, account := range t.accounts {
		return t.preimages[addrHash], account
	}
	return common.Address{}, nil
}

func (t *tester) generateStorage(ctx *genctx, addr common.Address) common.Hash {
	var (
		addrHash = crypto.Keccak256Hash(addr.Bytes())
		storage  = make(map[common.Hash][]byte)
		origin   = make(map[common.Hash][]byte)
	)
	for i := 0; i < 10; i++ {
		v, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(testutil.RandBytes(32)))
		hash := testutil.RandomHash()

		storage[hash] = v
		origin[hash] = nil
	}
	root, set := updateTrie(addrHash, types.EmptyRootHash, storage, nil)

	ctx.storages[addrHash] = storage
	ctx.storageOrigin[addr] = origin
	ctx.nodes.Merge(set)
	return root
}

func (t *tester) mutateStorage(ctx *genctx, addr common.Address, root common.Hash) common.Hash {
	var (
		addrHash = crypto.Keccak256Hash(addr.Bytes())
		storage  = make(map[common.Hash][]byte)
		origin   = make(map[common.Hash][]byte)
	)
	for hash, val := range t.storages[addrHash] {
		origin[hash] = val
		storage[hash] = nil

		if len(origin) == 3 {
			break
		}
	}
	for i := 0; i < 3; i++ {
		v, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(testutil.RandBytes(32)))
		hash := testutil.RandomHash()

		storage[hash] = v
		origin[hash] = nil
	}
	root, set := updateTrie(crypto.Keccak256Hash(addr.Bytes()), root, storage, t.storages[addrHash])

	ctx.storages[addrHash] = storage
	ctx.storageOrigin[addr] = origin
	ctx.nodes.Merge(set)
	return root
}

func (t *tester) clearStorage(ctx *genctx, addr common.Address, root common.Hash) common.Hash {
	var (
		addrHash = crypto.Keccak256Hash(addr.Bytes())
		storage  = make(map[common.Hash][]byte)
		origin   = make(map[common.Hash][]byte)
	)
	for hash, val := range t.storages[addrHash] {
		origin[hash] = val
		storage[hash] = nil
	}
	root, set := updateTrie(addrHash, root, storage, t.storages[addrHash])
	if root != types.EmptyRootHash {
		panic("failed to clear storage trie")
	}
	ctx.storages[addrHash] = storage
	ctx.storageOrigin[addr] = origin
	ctx.nodes.Merge(set)
	return root
}

func (t *tester) generate(parent common.Hash, sweep bool) (common.Hash, *trienode.MergedNodeSet, *triestate.Set) {
	// Save state snapshot
	t.snapAccounts[parent] = copyAccounts(t.accounts)
	t.snapStorages[parent] = copyStorages(t.storages)
	if sweep {
		parent = types.EmptyRootHash
		t.reset()
	}
	var (
		ctx     = newCtx()
		dirties = make(map[common.Hash]struct{})
	)
	for i := 0; i < 20; i++ {
		switch rand.Intn(opLen) {
		case createAccountOp:
			// account creation
			addr := testutil.RandomAddress()
			addrHash := crypto.Keccak256Hash(addr.Bytes())
			if _, ok := t.accounts[addrHash]; ok {
				continue
			}
			if _, ok := dirties[addrHash]; ok {
				continue
			}
			dirties[addrHash] = struct{}{}

			root := t.generateStorage(ctx, addr)
			ctx.accounts[addrHash] = types.SlimAccountRLP(generateAccount(root))
			ctx.accountOrigin[addr] = nil
			t.preimages[addrHash] = addr

		case modifyAccountOp:
			// account mutation
			addr, account := t.randAccount()
			if addr == (common.Address{}) {
				continue
			}
			addrHash := crypto.Keccak256Hash(addr.Bytes())
			if _, ok := dirties[addrHash]; ok {
				continue
			}
			dirties[addrHash] = struct{}{}

			acct, _ := types.FullAccount(account)
			stRoot := t.mutateStorage(ctx, addr, acct.Root)
			newAccount := types.SlimAccountRLP(generateAccount(stRoot))

			ctx.accounts[addrHash] = newAccount
			ctx.accountOrigin[addr] = account

		case deleteAccountOp:
			// account deletion
			addr, account := t.randAccount()
			if addr == (common.Address{}) {
				continue
			}
			addrHash := crypto.Keccak256Hash(addr.Bytes())
			if _, ok := dirties[addrHash]; ok {
				continue
			}
			dirties[addrHash] = struct{}{}

			acct, _ := types.FullAccount(account)
			if acct.Root != types.EmptyRootHash {
				t.clearStorage(ctx, addr, acct.Root)
			}
			ctx.accounts[addrHash] = nil
			ctx.accountOrigin[addr] = account
		}
	}
	root, set := updateTrie(common.Hash{}, parent, ctx.accounts, t.accounts)
	ctx.nodes.Merge(set)

	// Commit all changes to live state set
	for addrHash, account := range ctx.accounts {
		if len(account) == 0 {
			delete(t.accounts, addrHash)
		} else {
			t.accounts[addrHash] = account
		}
	}
	for addrHash, slots := range ctx.storages {
		if _, ok := t.storages[addrHash]; !ok {
			t.storages[addrHash] = make(map[common.Hash][]byte)
		}
		for sHash, slot := range slots {
			if len(slot) == 0 {
				delete(t.storages[addrHash], sHash)
			} else {
				t.storages[addrHash][sHash] = slot
			}
		}
	}
	return root, ctx.nodes, triestate.New(ctx.accountOrigin, ctx.storageOrigin, nil)
}

func (t *tester) reset() {
	t.accounts = make(map[common.Hash][]byte)
	t.storages = make(map[common.Hash]map[common.Hash][]byte)
}

// lastRoot returns the latest root hash, or empty if nothing is cached.
func (t *tester) lastHash() common.Hash {
	if len(t.roots) == 0 {
		return common.Hash{}
	}
	return t.roots[len(t.roots)-1]
}

// lastCkptHash returns the latest checkpoint root hash, or empty if nothing is cached.
func (t *tester) lastCkptHash() common.Hash {
	if len(t.roots) <= int(t.sweepEpoch) {
		return types.EmptyRootHash
	}
	number := len(t.roots) - 1
	lastCkptNumber := (number/int(t.sweepEpoch))*int(t.sweepEpoch) - 1
	return t.roots[lastCkptNumber]
}

func (t *tester) verifyState(epoch uint32, root common.Hash) error {
	reader, err := t.db.Reader(root, epoch)
	if err != nil {
		return err
	}
	_, err = reader.Node(common.Hash{}, nil, root)
	if err != nil {
		return errors.New("root node is not available")
	}
	for addrHash, account := range t.snapAccounts[root] {
		blob, err := reader.Node(common.Hash{}, addrHash.Bytes(), crypto.Keccak256Hash(account))
		if err != nil || !bytes.Equal(blob, account) {
			return fmt.Errorf("account is mismatched: %w", err)
		}
	}
	for addrHash, slots := range t.snapStorages[root] {
		for hash, slot := range slots {
			blob, err := reader.Node(addrHash, hash.Bytes(), crypto.Keccak256Hash(slot))
			if err != nil || !bytes.Equal(blob, slot) {
				return fmt.Errorf("slot is mismatched: %w", err)
			}
		}
	}
	return nil
}

func (t *tester) verifyCkptState(epoch uint32, root, ckptRoot common.Hash) error {
	reader, err := t.db.Reader(root, epoch)
	if err != nil {
		return err
	}
	ckptReader, err := t.db.Reader(ckptRoot, epoch-1)
	if err != nil {
		return err
	}
	_, err = reader.Node(common.Hash{}, nil, root)
	if err != nil {
		return errors.New("root node is not available")
	}
	_, err = ckptReader.Node(common.Hash{}, nil, ckptRoot)
	if err != nil {
		return errors.New("checkpoint root node is not available")
	}
	for addrHash, account := range t.snapAccounts[ckptRoot] {
		blob, err := ckptReader.Node(common.Hash{}, addrHash.Bytes(), crypto.Keccak256Hash(account))
		if err != nil || !bytes.Equal(blob, account) {
			return fmt.Errorf("account is mismatched: %w", err)
		}
	}
	for addrHash, slots := range t.snapStorages[ckptRoot] {
		for hash, slot := range slots {
			blob, err := ckptReader.Node(addrHash, hash.Bytes(), crypto.Keccak256Hash(slot))
			if err != nil || !bytes.Equal(blob, slot) {
				blob, err := reader.Node(addrHash, hash.Bytes(), crypto.Keccak256Hash(slot))
				if err != nil || !bytes.Equal(blob, slot) {
					return fmt.Errorf("slot is mismatched: %w", err)
				}
			}
		}
	}
	return nil
}

func (t *tester) verifyHistory() error {
	bottom := t.bottomIndex()
	for i, root := range t.roots {
		// The state history related to the state above disk layer should not exist.
		if i > bottom {
			_, err := readHistory(t.db.freezer, uint64(i+1))
			if err == nil {
				return errors.New("unexpected state history")
			}
			continue
		}
		// The state history related to the state below or equal to the disk layer
		// should exist.
		obj, err := readHistory(t.db.freezer, uint64(i+1))
		if err != nil {
			return err
		}
		parent := types.EmptyRootHash
		if i != 0 {
			parent = t.roots[i-1]
		}
		if obj.meta.parent != parent {
			return fmt.Errorf("unexpected parent, want: %x, got: %x", parent, obj.meta.parent)
		}
		if obj.meta.root != root {
			return fmt.Errorf("unexpected root, want: %x, got: %x", root, obj.meta.root)
		}
	}
	return nil
}

// bottomIndex returns the index of current disk layer.
func (t *tester) bottomIndex() int {
	bottom := t.db.tree.bottom()
	for i := 0; i < len(t.roots); i++ {
		if t.roots[i] == bottom.rootHash() {
			return i
		}
	}
	return -1
}

func TestBasic(t *testing.T)            { testBasic(t, BlockLength) }
func TestBasicWithEthanos(t *testing.T) { testBasic(t, SweepEpoch) }

func testBasic(t *testing.T, sweepEpoch uint32) {
	tester := newTester(t, sweepEpoch, 0)
	defer tester.release()

	for i := int(BlockLength - 1); i >= 0; i-- {
		if uint32(tester.bottomIndex()) > uint32(i) && uint32(i)%tester.sweepEpoch != tester.sweepEpoch-1 {
			continue
		}
		root := tester.roots[i]
		epoch := uint32(i) / tester.sweepEpoch
		var ckptRoot = types.EmptyRootHash
		if i > 0 {
			if epoch > 0 {
				ckptIndex := epoch*tester.sweepEpoch - 1
				ckptRoot = tester.roots[ckptIndex]
			}
		}
		if err := tester.verifyState(epoch, root); err != nil {
			t.Fatalf("Failed to verify state, err: %v", err)
		}
		if epoch > 0 {
			if err := tester.verifyCkptState(epoch, root, ckptRoot); err != nil {
				t.Fatalf("Failed to verify checkpoint state, err: %v", err)
			}
		}
	}
}

func TestDatabaseRollback(t *testing.T)            { testDatabaseRollback(t, BlockLength) }
func TestDatabaseRollbackWithEthanos(t *testing.T) { testDatabaseRollback(t, SweepEpoch) }

func testDatabaseRollback(t *testing.T, sweepEpoch uint32) {
	// Verify state histories
	tester := newTester(t, sweepEpoch, 0)
	defer tester.release()

	if err := tester.verifyHistory(); err != nil {
		t.Fatalf("Invalid state history, err: %v", err)
	}

	bottomEpoch := uint32(tester.bottomIndex()) / tester.sweepEpoch
	// Revert database from top to bottom
	for i := tester.bottomIndex(); i >= 0; i-- {
		root := tester.roots[i]
		parentEpoch := uint32(0)
		parentRoot := types.EmptyRootHash
		parentCkptRoot := types.EmptyRootHash
		if i > 0 {
			parentRoot = tester.roots[i-1]
			parentEpoch = uint32(i-1) / tester.sweepEpoch
			if parentEpoch > 0 {
				ckptIndex := parentEpoch*tester.sweepEpoch - 1
				parentCkptRoot = tester.roots[ckptIndex]
			}
		}
		loader := newHashLoader(tester.snapAccounts[root], tester.snapStorages[root])
		if bottomEpoch == parentEpoch {
			if err := tester.db.Recover(parentEpoch, parentRoot, parentCkptRoot, loader); err != nil {
				t.Fatalf("Failed to revert db, err: %v", err)
			}
		} else {
			if err := tester.db.Recover(parentEpoch, parentRoot, parentCkptRoot, loader); err == nil ||
				err.Error() != "state is unrecoverable" {
				t.Fatalf("Unexpected error, want: state is unrecoverable, got: %v", err)
			}
			continue
		}
		if i > 0 {
			if err := tester.verifyState(parentEpoch, parentRoot); err != nil {
				t.Fatalf("Failed to verify state, err: %v", err)
			}
			if parentEpoch > 0 {
				if err := tester.verifyCkptState(parentEpoch, parentRoot, parentCkptRoot); err != nil {
					t.Fatalf("Failed to verify checkpoint state, err: %v", err)
				}
			}
		}
	}
	if tester.db.tree.len() != 1 {
		t.Fatal("Only disk layer is expected")
	}
}

func TestDatabaseRecoverable(t *testing.T) {
	var (
		tester = newTester(t, BlockLength, 0)
		index  = tester.bottomIndex()
	)

	calcEpoch := func(index int) uint32 {
		return uint32(index) / tester.sweepEpoch
	}
	calcCkptRoot := func(index int) common.Hash {
		epoch := calcEpoch(index)
		if epoch == 0 {
			return types.EmptyRootHash
		}
		ckptIndex := epoch*tester.sweepEpoch - 1
		return tester.roots[ckptIndex]
	}
	defer tester.release()

	var cases = []struct {
		epoch    uint32
		root     common.Hash
		ckptRoot common.Hash
		expect   bool
	}{
		// Unknown state should be unrecoverable
		{0, common.Hash{0x1}, common.Hash{0x1}, false},

		// Initial state should be recoverable
		{0, types.EmptyRootHash, types.EmptyRootHash, true},

		// Initial state should be recoverable
		{0, common.Hash{}, common.Hash{}, true},

		// Layers below current disk layer are recoverable
		{0, tester.roots[index+1], calcCkptRoot(index - 1), false},

		// Disklayer itself is not recoverable, since it's
		// available for accessing.
		{0, tester.roots[index], calcCkptRoot(index), false},

		// Layers above current disk layer are not recoverable
		// since they are available for accessing.
		{0, tester.roots[index+1], calcCkptRoot(index + 1), false},
	}

	// All states below current disk layer should be recoverable.
	for i := index - 1; i >= 0; i-- {
		cases = append(cases, struct {
			epoch    uint32
			root     common.Hash
			ckptRoot common.Hash
			expect   bool
		}{
			calcEpoch(i), tester.roots[i], calcCkptRoot(i), true,
		})
	}

	for i, c := range cases {
		result := tester.db.Recoverable(c.epoch, c.root, c.ckptRoot)
		if result != c.expect {
			t.Fatalf("case: %d, unexpected result, want %t, got %t", i, c.expect, result)
		}
	}
}
func TestDatabaseRecoverableWithEthanos(t *testing.T) {
	var (
		tester = newTester(t, SweepEpoch, 0)
		index  = tester.bottomIndex()
	)

	calcEpoch := func(index int) uint32 {
		return uint32(index) / tester.sweepEpoch
	}
	calcCkptRoot := func(index int) common.Hash {
		epoch := calcEpoch(index)
		if epoch == 0 {
			return types.EmptyRootHash
		}
		ckptIndex := epoch*tester.sweepEpoch - 1
		return tester.roots[ckptIndex]
	}
	defer tester.release()

	var cases = []struct {
		epoch    uint32
		root     common.Hash
		ckptRoot common.Hash
		expect   bool
	}{}
	// All states below current disk layer should be recoverable.
	for i := index - 1; i >= 0; i-- {
		cases = append(cases, struct {
			epoch    uint32
			root     common.Hash
			ckptRoot common.Hash
			expect   bool
		}{
			calcEpoch(i), tester.roots[i], calcCkptRoot(i), calcEpoch(index) == calcEpoch(i),
		})
	}

	for i, c := range cases {
		result := tester.db.Recoverable(c.epoch, c.root, c.ckptRoot)
		if result != c.expect {
			t.Fatalf("case: %d, unexpected result, want %t, got %t", i, c.expect, result)
		}
	}
}

func TestDisable(t *testing.T)            { testDisable(t, BlockLength) }
func TestDisableWithEthanos(t *testing.T) { testDisable(t, SweepEpoch) }
func testDisable(t *testing.T, sweepEpoch uint32) {
	tester := newTester(t, sweepEpoch, 0)
	defer tester.release()

	epoch := rawdb.ReadPersistentEpoch(tester.db.diskdb)
	_, stored := rawdb.ReadAccountTrieNode(tester.db.diskdb, epoch, nil)
	var ckptStored = types.EmptyRootHash
	if epoch > 0 {
		_, ckptStored = rawdb.ReadAccountTrieNode(tester.db.diskdb, epoch-1, nil)
	}
	if err := tester.db.Disable(); err != nil {
		t.Fatal("Failed to deactivate database")
	}
	if err := tester.db.Enable(types.EmptyRootHash, types.EmptyRootHash, 0); err == nil {
		t.Fatalf("Invalid activation should be rejected")
	}
	if err := tester.db.Enable(stored, ckptStored, epoch); err != nil {
		t.Fatal("Failed to activate database")
	}

	// Ensure journal is deleted from disk
	if blob := rawdb.ReadTrieJournal(tester.db.diskdb); len(blob) != 0 {
		t.Fatal("Failed to clean journal")
	}
	// Ensure all trie histories are removed
	n, err := tester.db.freezer.Ancients()
	if err != nil {
		t.Fatal("Failed to clean state history")
	}
	if n != 0 {
		t.Fatal("Failed to clean state history")
	}
	// Verify layer tree structure, one disk layer is expected
	if tester.db.tree.len() != 1 {
		t.Fatalf("Extra layer kept %d", tester.db.tree.len())
	}
	if tester.db.tree.bottom().rootHash() != stored {
		t.Fatalf("Root hash is not matched exp %x got %x", stored, tester.db.tree.bottom().rootHash())
	}
	if tester.db.tree.ckptBottom().rootHash() != ckptStored {
		t.Fatalf("Checkpoint Root hash is not matched exp %x got %x", ckptStored, tester.db.tree.ckptBottom().rootHash())
	}
}

func TestCommit(t *testing.T)            { testCommit(t, BlockLength) }
func TestCommitWithEthanos(t *testing.T) { testCommit(t, SweepEpoch) }
func testCommit(t *testing.T, sweepEpoch uint32) {
	tester := newTester(t, sweepEpoch, 0)
	defer tester.release()

	if err := tester.db.Commit(tester.lastHash(), false); err != nil {
		t.Fatalf("Failed to cap database, err: %v", err)
	}
	// Verify layer tree structure, one disk layer is expected
	if tester.db.tree.len() != 1 {
		t.Fatal("Layer tree structure is invalid")
	}
	if tester.db.tree.bottom().rootHash() != tester.lastHash() {
		t.Fatal("Layer tree structure is invalid")
	}
	if tester.db.tree.ckptBottom().rootHash() != tester.lastCkptHash() {
		t.Fatal("Layer tree structure is invalid")
	}
	// Verify states
	lastBlockNumber := uint32(len(tester.roots) - 1)
	lastEpoch := lastBlockNumber / tester.sweepEpoch
	if err := tester.verifyState(lastEpoch, tester.lastHash()); err != nil {
		t.Fatalf("State is invalid, err: %v", err)
	}
	if lastEpoch > 0 {
		ckptIndex := lastEpoch*tester.sweepEpoch - 1
		ckptRoot := tester.roots[ckptIndex]
		if err := tester.verifyCkptState(lastEpoch, tester.lastHash(), ckptRoot); err != nil {
			t.Fatalf("Checkpoint State is invalid, err: %v", err)
		}
	}
	// Verify state histories
	if err := tester.verifyHistory(); err != nil {
		t.Fatalf("State history is invalid, err: %v", err)
	}
}

func TestJournal(t *testing.T)            { testJournal(t, BlockLength) }
func TestJournalWithEthanos(t *testing.T) { testJournal(t, SweepEpoch) }
func testJournal(t *testing.T, sweepEpoch uint32) {
	tester := newTester(t, sweepEpoch, 0)
	defer tester.release()

	if err := tester.db.Journal(tester.lastHash()); err != nil {
		t.Errorf("Failed to journal, err: %v", err)
	}
	tester.db.Close()
	tester.db = New(tester.db.diskdb, nil)

	// Verify states including disk layer and all diff on top.
	for i := 0; i < len(tester.roots); i++ {
		epoch := uint32(i) / tester.sweepEpoch
		if i >= tester.bottomIndex() || uint32(i)%tester.sweepEpoch == tester.sweepEpoch-1 {
			if err := tester.verifyState(epoch, tester.roots[i]); err != nil {
				t.Fatalf("Invalid state, err: %v", err)
			}
			continue
		}
		if err := tester.verifyState(epoch, tester.roots[i]); err == nil {
			t.Fatal("Unexpected state")
		}
	}
}
func TestCorruptedJournal(t *testing.T)            { testCorruptedJournal(t, BlockLength) }
func TestCorruptedJournalWithEthanos(t *testing.T) { testCorruptedJournal(t, SweepEpoch) }
func testCorruptedJournal(t *testing.T, sweepEpoch uint32) {
	tester := newTester(t, sweepEpoch, 0)
	defer tester.release()

	if err := tester.db.Journal(tester.lastHash()); err != nil {
		t.Errorf("Failed to journal, err: %v", err)
	}
	tester.db.Close()
	epoch := rawdb.ReadPersistentEpoch(tester.db.diskdb)
	_, root := rawdb.ReadAccountTrieNode(tester.db.diskdb, epoch, nil)

	// Mutate the journal in disk, it should be regarded as invalid
	blob := rawdb.ReadTrieJournal(tester.db.diskdb)
	blob[0] = 1
	rawdb.WriteTrieJournal(tester.db.diskdb, blob)

	// Verify states, all not-yet-written states should be discarded
	tester.db = New(tester.db.diskdb, nil)
	for i := 0; i < len(tester.roots); i++ {
		if tester.roots[i] == root || uint32(i)%tester.sweepEpoch == tester.sweepEpoch-1 {
			if err := tester.verifyState(epoch, root); err != nil {
				t.Fatalf("Disk state is corrupted, err: %v", err)
			}
			continue
		}
		if err := tester.verifyState(uint32(i)/tester.sweepEpoch, tester.roots[i]); err == nil {
			t.Fatal("Unexpected state")
		}
	}
}

// TestTailTruncateHistory function is designed to test a specific edge case where,
// when history objects are removed from the end, it should trigger a state flush
// if the ID of the new tail object is even higher than the persisted state ID.
//
// For example, let's say the ID of the persistent state is 10, and the current
// history objects range from ID(5) to ID(15). As we accumulate six more objects,
// the history will expand to cover ID(11) to ID(21). ID(11) then becomes the
// oldest history object, and its ID is even higher than the stored state.
//
// In this scenario, it is mandatory to update the persistent state before
// truncating the tail histories. This ensures that the ID of the persistent state
// always falls within the range of [oldest-history-id, latest-history-id].

func TestTailTruncateHistory(t *testing.T) {
	tester := newTester(t, BlockLength, 10)
	defer tester.release()

	tester.db.Close()
	tester.db = New(tester.db.diskdb, &Config{StateHistory: 10})

	head, err := tester.db.freezer.Ancients()
	if err != nil {
		t.Fatalf("Failed to obtain freezer head")
	}
	stored := rawdb.ReadPersistentStateID(tester.db.diskdb)
	if head != stored {
		t.Fatalf("Failed to truncate excess history object above, stored: %d, head: %d", stored, head)
	}
}

// copyAccounts returns a deep-copied account set of the provided one.
func copyAccounts(set map[common.Hash][]byte) map[common.Hash][]byte {
	copied := make(map[common.Hash][]byte, len(set))
	for key, val := range set {
		copied[key] = common.CopyBytes(val)
	}
	return copied
}

// copyStorages returns a deep-copied storage set of the provided one.
func copyStorages(set map[common.Hash]map[common.Hash][]byte) map[common.Hash]map[common.Hash][]byte {
	copied := make(map[common.Hash]map[common.Hash][]byte, len(set))
	for addrHash, subset := range set {
		copied[addrHash] = make(map[common.Hash][]byte, len(subset))
		for key, val := range subset {
			copied[addrHash][key] = common.CopyBytes(val)
		}
	}
	return copied
}
