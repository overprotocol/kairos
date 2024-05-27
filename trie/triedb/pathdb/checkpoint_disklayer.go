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
	"sync"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/triestate"
)

// ckptDiskLayer is a low level persistent layer built on top of a key-value store.
type ckptDiskLayer struct {
	root   common.Hash      // Immutable, root hash to which this layer was made for
	epoch  uint32           // Epoch which the layer belongs
	db     *Database        // Path-based trie database
	cleans *fastcache.Cache // GC friendly memory cache of clean node RLPs
	stale  bool             // Signals that the layer became stale (state progressed)
	lock   sync.RWMutex     // Lock used to protect stale flag
}

// newCkptDiskLayer creates a new disk layer based on the passing arguments.
func newCkptDiskLayer(root common.Hash, epoch uint32, db *Database, cleans *fastcache.Cache) *ckptDiskLayer {
	return &ckptDiskLayer{
		root:   root,
		epoch:  epoch,
		db:     db,
		cleans: cleans,
	}
}

// rootHash implements the layer interface, returning root hash of corresponding state.
func (dl *ckptDiskLayer) rootHash() common.Hash {
	return dl.root
}

// stateID implements the layer interface, returning the state id of disk layer.
func (dl *ckptDiskLayer) stateID() uint64 {
	return 0
}

// epochNumber implements the layer interface, returning the epoch of the layer.
func (dl *ckptDiskLayer) epochNumber() uint32 {
	return dl.epoch
}

// parentLayer implements the layer interface, returning nil as there's no layer
// below the disk.
func (dl *ckptDiskLayer) parentLayer() layer {
	return nil
}

// markStale sets the stale flag as true.
func (dl *ckptDiskLayer) markStale() {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	if dl.stale {
		panic("triedb disk layer is stale") // we've committed into the same base from two children, boom
	}
	dl.stale = true
}

// Node implements the layer interface, retrieving the trie node with the
// provided node info. No error will be returned if the node is not found.
func (dl *ckptDiskLayer) Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error) {
	// Try to retrieve the trie node from the clean memory cache
	key := cacheKey(owner, dl.epoch, path)
	if dl.cleans != nil {
		if blob := dl.cleans.Get(nil, key); len(blob) > 0 {
			h := newHasher()
			defer h.release()

			got := h.hash(blob)
			if got == hash {
				cleanHitMeter.Mark(1)
				cleanReadMeter.Mark(int64(len(blob)))
				return blob, nil
			}
			cleanFalseMeter.Mark(1)
			log.Error("Unexpected trie node in clean cache", "owner", owner, "path", path, "expect", hash, "got", got)
		}
		cleanMissMeter.Mark(1)
	}
	// Try to retrieve the trie node from the disk.
	var (
		nBlob []byte
		nHash common.Hash
	)
	if owner == (common.Hash{}) {
		nBlob, nHash = rawdb.ReadAccountTrieNode(dl.db.diskdb, dl.epochNumber(), path)
	} else {
		nBlob, nHash = rawdb.ReadStorageTrieNode(dl.db.diskdb, owner, path)
	}
	if nHash != hash {
		diskFalseMeter.Mark(1)
		log.Error("Unexpected trie node in disk", "owner", owner, "path", path, "expect", hash, "got", nHash)
		return nil, newUnexpectedNodeError("disk", hash, nHash, owner, path, nBlob)
	}
	if dl.cleans != nil && len(nBlob) > 0 {
		dl.cleans.Set(key, nBlob)
		cleanWriteMeter.Mark(int64(len(nBlob)))
	}
	return nBlob, nil
}

func (dl *ckptDiskLayer) update(root common.Hash, id uint64, epoch uint32, block uint64, nodes map[common.Hash]map[string]*trienode.Node, states *triestate.Set) *diffLayer {
	log.Warn("Update called on checkpoint disk layer in pathdb", "root", root, "id", id, "epoch", epoch)
	return nil
}
