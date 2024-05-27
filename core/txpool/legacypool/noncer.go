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

package legacypool

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

// noncer is a tiny virtual state database to manage the executable nonces of
// accounts in the pool, falling back to reading from a real state database if
// an account is unknown.
type noncer struct {
	fallback *state.StateDB
	txNonces map[common.Address]nonceEpochCoverage
	lock     sync.Mutex
}

type nonceEpochCoverage struct {
	epochCoverage uint32
	nonce         uint32
}

// newNoncer creates a new virtual state database to track the pool nonces.
func newNoncer(statedb *state.StateDB) *noncer {
	return &noncer{
		fallback: statedb.Copy(),
		txNonces: make(map[common.Address]nonceEpochCoverage),
	}
}

// getNonce returns the current nonce of an account, falling back to a real state
// database if the account is unknown.
func (txn *noncer) getNonce(addr common.Address) uint32 {
	// We use mutex for get operation is the underlying
	// state will mutate db even for read access.
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.txNonces[addr]; !ok {
		if nonce := txn.fallback.GetTxNonce(addr); nonce != 0 {
			txn.txNonces[addr] = nonceEpochCoverage{
				epochCoverage: types.TxNonceToMsgEpochCoverage(nonce),
				nonce:         types.TxNonceToMsgNonce(nonce),
			}
		}
	}
	return txn.txNonces[addr].nonce
}

// getEpochCoverage returns the current epochCoverage of an account, falling back to a real state
// database if the account is unknown.
func (txn *noncer) getEpochCoverage(addr common.Address) uint32 {
	// We use mutex for get operation is the underlying
	// state will mutate db even for read access.
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.txNonces[addr]; !ok {
		if nonce := txn.fallback.GetTxNonce(addr); nonce != 0 {
			txn.txNonces[addr] = nonceEpochCoverage{
				epochCoverage: types.TxNonceToMsgEpochCoverage(nonce),
				nonce:         types.TxNonceToMsgNonce(nonce),
			}
		}
	}
	return txn.txNonces[addr].epochCoverage
}

// set inserts a new virtual nonce into the virtual state database to be returned
// whenever the pool requests it instead of reaching into the real state database.
func (txn *noncer) set(addr common.Address, txNonce nonceEpochCoverage) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.txNonces[addr] = nonceEpochCoverage{
		epochCoverage: txNonce.epochCoverage,
		nonce:         txNonce.nonce,
	}
}

// setIfLower updates a new virtual nonce into the virtual state database if the
// new one is lower.
func (txn *noncer) setIfLower(addr common.Address, txNonce nonceEpochCoverage) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.txNonces[addr]; !ok {
		if nonce := txn.fallback.GetTxNonce(addr); nonce != 0 {
			txn.txNonces[addr] = nonceEpochCoverage{
				epochCoverage: types.TxNonceToMsgEpochCoverage(nonce),
				nonce:         types.TxNonceToMsgNonce(nonce),
			}
		}
	}
	if txNonce.epochCoverage != txn.txNonces[addr].epochCoverage {
		return
	}
	if txn.txNonces[addr].nonce <= txNonce.nonce {
		return
	}
	txn.txNonces[addr] = nonceEpochCoverage{
		nonce:         txNonce.nonce,
		epochCoverage: txNonce.epochCoverage,
	}
}

// setAll sets the nonces for all accounts to the given map.
func (txn *noncer) setAll(all map[common.Address]nonceEpochCoverage) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.txNonces = all
}
