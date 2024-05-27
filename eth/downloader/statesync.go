// Copyright 2017 The go-ethereum Authors
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
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// syncState starts downloading state with the given root hash.
func (d *Downloader) syncState(epoch uint32, root, ckptRoot common.Hash) *stateSync {
	// Create the state sync
	s := newStateSync(d, epoch, root, ckptRoot)
	select {
	case d.stateSyncStart <- s:
		// If we tell the statesync to restart with a new root, we also need
		// to wait for it to actually also start -- when old requests have timed
		// out or been delivered
		<-s.started
	case <-d.quitCh:
		s.err = errCancelStateFetch
		close(s.done)
	}
	return s
}

// stateFetcher manages the active state sync and accepts requests
// on its behalf.
func (d *Downloader) stateFetcher() {
	for {
		select {
		case s := <-d.stateSyncStart:
			for next := s; next != nil; {
				next = d.runStateSync(next)
			}
		case <-d.quitCh:
			return
		}
	}
}

// runStateSync runs a state synchronisation until it completes or another root
// hash is requested to be switched over to.
func (d *Downloader) runStateSync(s *stateSync) *stateSync {
	log.Trace("State sync starting", "root", s.root)

	go s.run()
	defer s.Cancel()

	for {
		select {
		case next := <-d.stateSyncStart:
			return next

		case <-s.done:
			return nil
		}
	}
}

// stateSync schedules requests for downloading a particular state trie defined
// by a given state root.
type stateSync struct {
	d        *Downloader // Downloader instance to access and manage current peerset
	epoch    uint32      // Epoch currently being synced
	root     common.Hash // State root currently being synced
	ckptRoot common.Hash // Checkpoint root currently being synced

	started    chan struct{} // Started is signalled once the sync loop starts
	cancel     chan struct{} // Channel to signal a termination request
	cancelOnce sync.Once     // Ensures cancel only ever gets called once
	done       chan struct{} // Channel to signal termination completion
	err        error         // Any error hit during sync (set before completion)
}

// newStateSync creates a new state trie download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newStateSync(d *Downloader, epoch uint32, root, ckptRoot common.Hash) *stateSync {
	return &stateSync{
		d:        d,
		epoch:    epoch,
		root:     root,
		ckptRoot: ckptRoot,
		cancel:   make(chan struct{}),
		done:     make(chan struct{}),
		started:  make(chan struct{}),
	}
}

// run starts the task assignment and response processing loop, blocking until
// it finishes, and finally notifying any goroutines waiting for the loop to
// finish.
func (s *stateSync) run() {
	close(s.started)
	// sync current trie first, then sync checkpoint trie
	s.err = s.d.SnapSyncer.Sync(s.epoch, s.root, false, s.cancel)
	if s.err == nil && s.epoch > 0 {
		s.err = s.d.SnapSyncer.Sync(s.epoch-1, s.ckptRoot, true, s.cancel)
	}
	close(s.done)
}

// Check if state sync needs to update the pivot
// If the root and checkpoint root has not changed, we don't need to update the
// pivot of the state sync
func (s *stateSync) needPivotUpdate(root, ckptRoot common.Hash) bool {
	return s.root != root || s.ckptRoot != ckptRoot
}

// Wait blocks until the sync is done or canceled.
func (s *stateSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
func (s *stateSync) Cancel() error {
	s.cancelOnce.Do(func() {
		close(s.cancel)
	})
	return s.Wait()
}
