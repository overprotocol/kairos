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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package pathdb

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/triestate"
)

// layerTree is a group of state layers identified by the state root.
// This structure defines a few basic operations for manipulating
// state layers linked with each other in a tree structure. It's
// thread-safe to use. However, callers need to ensure the thread-safety
// of the referenced layer by themselves.
type layerTree struct {
	lock      sync.RWMutex
	layers    map[common.Hash]layer
	diskLayer *diskLayer
}

// newLayerTree constructs the layerTree with the given head layer.
func newLayerTree(head layer) *layerTree {
	tree := new(layerTree)
	tree.reset(head)
	return tree
}

// reset initializes the layerTree by the given head layer.
// All the ancestors will be iterated out and linked in the tree.
func (tree *layerTree) reset(head layer) {
	tree.lock.Lock()
	defer tree.lock.Unlock()

	var layers = make(map[common.Hash]layer)
	for head != nil {
		if dl, ok := head.(*diskLayer); ok {
			tree.diskLayer = dl
		}
		layers[head.rootHash()] = head
		head = head.parentLayer()
	}
	tree.layers = layers
}

// get retrieves a layer belonging to the given state root.
func (tree *layerTree) get(root common.Hash) layer {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	if layer, ok := tree.layers[types.TrieRootHash(root)]; ok {
		return layer
	} else if ckptLayer := tree.ckptBottom(); ckptLayer != nil && ckptLayer.rootHash() == types.TrieRootHash(root) {
		return ckptLayer
	}
	return nil
}

// forEach iterates the stored layers inside and applies the
// given callback on them.
func (tree *layerTree) forEach(onLayer func(layer)) {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	for _, layer := range tree.layers {
		onLayer(layer)
	}
}

// len returns the number of layers cached.
func (tree *layerTree) len() int {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	return len(tree.layers)
}

// add inserts a new layer into the tree if it can be linked to an existing old parent.
func (tree *layerTree) add(root common.Hash, parentRoot common.Hash, epoch uint32, block uint64, nodes *trienode.MergedNodeSet, states *triestate.Set) error {
	// Reject noop updates to avoid self-loops. This is a special case that can
	// happen for clique networks and proof-of-stake networks where empty blocks
	// don't modify the state (0 block subsidy).
	//
	// Although we could silently ignore this internally, it should be the caller's
	// responsibility to avoid even attempting to insert such a layer.
	root, parentRoot = types.TrieRootHash(root), types.TrieRootHash(parentRoot)
	if root == parentRoot {
		return errors.New("layer cycle")
	}
	parent := tree.get(parentRoot)
	if parent == nil {
		return fmt.Errorf("triedb parent [%#x] layer missing", parentRoot)
	}
	// In case the parent is an empty layer and epoch is not 0, we need to
	// replace the empty layer with the new layer.
	if parent.rootHash() == types.EmptyRootHash && parent.epochNumber() > 0 {
		tree.lock.Lock()
		delete(tree.layers, types.EmptyRootHash)
		tree.lock.Unlock()
		parent = parent.parentLayer()
		if parent == nil {
			return errors.New("triedb empty layer not linked to previous epoch")
		}
	}
	l := parent.update(root, parent.stateID()+1, epoch, block, nodes.Flatten(), states)

	tree.lock.Lock()
	tree.layers[l.rootHash()] = l
	tree.lock.Unlock()
	return nil
}

// cap traverses downwards the diff tree until the number of allowed diff layers
// are crossed. All diffs beyond the permitted number are flattened downwards.
func (tree *layerTree) cap(root common.Hash, layers int) error {
	// Retrieve the head layer to cap from
	root = types.TrieRootHash(root)
	l := tree.get(root)
	if l == nil {
		return fmt.Errorf("triedb layer [%#x] missing", root)
	}
	diff, ok := l.(*diffLayer)
	if !ok {
		return fmt.Errorf("triedb layer [%#x] is disk layer", root)
	}
	tree.lock.Lock()
	defer tree.lock.Unlock()

	// If full commit was requested, flatten the diffs and merge onto disk
	if layers == 0 {
		base, err := diff.persist(true)
		if err != nil {
			return err
		}
		// Replace the entire layer tree with the flat base
		tree.layers = map[common.Hash]layer{base.rootHash(): base}
		tree.diskLayer = base.(*diskLayer)
		return nil
	}
	// Dive until we run out of layers or reach the persistent database
	for i := 0; i < layers-1; i++ {
		// If we still have diff layers below, continue down
		if parent, ok := diff.parentLayer().(*diffLayer); ok {
			diff = parent
		} else {
			// Diff stack too shallow, return without modifications
			return nil
		}
	}
	// We're out of layers, flatten anything below, stopping if it's the disk or if
	// the memory limit is not yet exceeded.
	switch parent := diff.parentLayer().(type) {
	case *diskLayer:
		return nil

	case *diffLayer:
		// Hold the lock to prevent any read operations until the new
		// parent is linked correctly.
		diff.lock.Lock()

		base, err := parent.persist(false)
		if err != nil {
			diff.lock.Unlock()
			return err
		}
		tree.layers[base.rootHash()] = base
		tree.diskLayer = base.(*diskLayer)
		diff.parent = base

		diff.lock.Unlock()

	default:
		panic(fmt.Sprintf("unknown data layer in triedb: %T", parent))
	}
	// Remove any layer that is stale or links into a stale layer
	children := make(map[common.Hash][]common.Hash)
	for root, layer := range tree.layers {
		if dl, ok := layer.(*diffLayer); ok {
			parent := dl.parentLayer().rootHash()
			children[parent] = append(children[parent], root)
		}
	}
	var remove func(root common.Hash)
	remove = func(root common.Hash) {
		delete(tree.layers, root)
		for _, child := range children[root] {
			remove(child)
		}
		delete(children, root)
	}
	for root, layer := range tree.layers {
		if dl, ok := layer.(*diskLayer); ok && dl.isStale() {
			remove(root)
		}
	}
	return nil
}

// addNewEpoch inserts a new empty layer into the tree. It is called at the start of each epoch.
// Note that the empty layer is going to be replaced when the next layer is inserted.
func (tree *layerTree) addNewEpoch(epoch uint32, root common.Hash) error {
	parent := tree.get(root)
	if parent == nil {
		return fmt.Errorf("triedb layer [%#x] missing", root)
	}
	if parent.epochNumber()+1 != epoch {
		return fmt.Errorf("triedb layer [%#x] epoch mismatch", root)
	}
	var (
		nodes  map[common.Hash]map[string]*trienode.Node
		states *triestate.Set
	)
	l := parent.update(types.EmptyRootHash, parent.stateID()+1, epoch, 0, nodes, states)

	tree.lock.Lock()
	tree.layers[l.rootHash()] = l
	tree.lock.Unlock()
	return nil
}

// bottom returns the bottom-most disk layer in this tree.
func (tree *layerTree) bottom() *diskLayer {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	return tree.diskLayer
}

// ckptBottom returns the checkpoint layer of this tree.
func (tree *layerTree) ckptBottom() *ckptDiskLayer {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	if tree.diskLayer == nil {
		log.Error("disk layer is empty")
		return nil // Shouldn't happen, empty tree
	}
	return tree.diskLayer.ckptLayer
}