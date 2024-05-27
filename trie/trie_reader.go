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

package trie

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/triestate"
)

// Reader wraps the Node method of a backing trie store.
type Reader interface {
	// Node retrieves the trie node blob with the provided trie identifier, node path and
	// the corresponding node hash. No error will be returned if the node is not found.
	//
	// When looking up nodes in the account trie, 'owner' is the zero hash. For contract
	// storage trie nodes, 'owner' is the hash of the account address that containing the
	// storage.
	//
	// TODO(rjl493456442): remove the 'hash' parameter, it's redundant in PBSS.
	Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error)
}

// trieReader is a wrapper of the underlying node reader. It's not safe
// for concurrent usage.
type trieReader struct {
	owner  common.Hash
	reader Reader
	banned map[string]struct{} // Marker to prevent node from being accessed, for tests
}

// newTrieReader initializes the trie reader with the given node reader.
func newTrieReader(epoch uint32, stateRoot, owner common.Hash, db *Database) (*trieReader, error) {
	reader, err := db.Reader(stateRoot, epoch)
	if err == nil {
		return &trieReader{owner: owner, reader: reader}, nil
	}
	if stateRoot == (common.Hash{}) || stateRoot == types.EmptyRootHash {
		if stateRoot == (common.Hash{}) {
			log.Error("Zero state root hash!")
		}
		return &trieReader{owner: owner}, nil
	}
	return nil, &MissingNodeError{Owner: owner, NodeHash: stateRoot, err: err}
}

// newEmptyReader initializes the pure in-memory reader. All read operations
// should be forbidden and returns the MissingNodeError.
func newEmptyReader() *trieReader {
	return &trieReader{}
}

// node retrieves the rlp-encoded trie node with the provided trie node
// information. An MissingNodeError will be returned in case the node is
// not found or any error is encountered.
func (r *trieReader) node(path []byte, hash common.Hash) ([]byte, error) {
	// Perform the logics in tests for preventing trie node access.
	if r.banned != nil {
		if _, ok := r.banned[string(path)]; ok {
			return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
		}
	}
	if r.reader == nil {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
	}
	blob, err := r.reader.Node(r.owner, path, hash)
	if err != nil || len(blob) == 0 {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path, err: err}
	}
	return blob, nil
}

// trieLoader implements triestate.TrieLoader for constructing tries.
type trieLoader struct {
	db    *Database
	epoch uint32
}

// OpenTrie opens the main account trie.
func (l *trieLoader) OpenTrie(root common.Hash) (triestate.Trie, error) {
	return New(StateTrieID(root, l.epoch), l.db)
}

// OpenStorageTrie opens the storage trie of an account.
func (l *trieLoader) OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash) (triestate.Trie, error) {
	return New(StorageTrieID(stateRoot, l.epoch, addrHash, root), l.db)
}
