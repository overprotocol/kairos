// Copyright 2015 The go-ethereum Authors
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

package ethapi

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// OverAPI provides an API to access Over related information.
type OverAPI struct {
	b Backend
}

// NewOverAPI creates a new Over protocol API.
func NewOverAPI(b Backend) *OverAPI {
	return &OverAPI{b}
}

func (api *OverAPI) SweepEpoch() hexutil.Uint64 {
	return hexutil.Uint64(api.b.ChainConfig().SweepEpoch)
}

func (api *OverAPI) NextCheckpointBlockNumber(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	header, err := api.b.HeaderByNumberOrHash(ctx, blockNrOrHash)
	if header != nil && err == nil {
		nextCheckpointBlockNumber := api.b.ChainConfig().CalcNextCheckpointBlockNumberByNumber(header.Number.Uint64())
		return (*hexutil.Uint64)(&nextCheckpointBlockNumber), nil
	}
	return nil, err
}

// GetEpoch returns the epoch value of the given block number.
func (api *OverAPI) GetEpoch(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (uint32, error) {
	header, err := api.b.HeaderByNumberOrHash(ctx, blockNrOrHash)
	if header != nil && err == nil {
		return api.b.CalcEpoch(header.Number.Uint64())
	}
	return 0, err
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (api *OverAPI) GetBalance(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash, withoutCkpt)
	if state == nil || err != nil {
		return nil, err
	}
	return (*hexutil.Big)(state.GetBalance(address)), state.Error()
}

// Exist returns the existence of the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (api *OverAPI) Exist(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (bool, error) {
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash, withoutCkpt)
	if state == nil || err != nil {
		return false, err
	}
	return state.Exist(address), state.Error()
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (api *OverAPI) GetCode(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash, withoutCkpt)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

func (api *OverAPI) getTransactionCount(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (uint64, error) {
	// Ask transaction pool for the nonce which includes pending transactions
	if blockNr, ok := blockNrOrHash.Number(); ok && blockNr == rpc.PendingBlockNumber {
		nonce, err := api.b.GetPoolNonce(ctx, address)
		if err != nil {
			return 0, err
		}
		return nonce, nil
	}
	// Resolve block number and use its state to ask for the nonce
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash, withoutCkpt)
	if state == nil || err != nil {
		return 0, err
	}
	txNonce := state.GetTxNonce(address)
	return txNonce, state.Error()
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (api *OverAPI) GetTransactionCount(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	txNonce, err := api.getTransactionCount(ctx, address, withoutCkpt, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Uint64)(&txNonce), nil
}

// GetNonce returns the nonce of the given address has sent for the given block number
func (api *OverAPI) GetNonce(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	txNonce, err := api.getTransactionCount(ctx, address, withoutCkpt, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	nonce := uint64(types.TxNonceToMsgNonce(txNonce))
	return (*hexutil.Uint64)(&nonce), nil
}

// GetEpochCoverage returns the epoch coverage of the given address has sent for the given block number
func (api *OverAPI) GetEpochCoverage(ctx context.Context, address common.Address, withoutCkpt bool, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	txNonce, err := api.getTransactionCount(ctx, address, withoutCkpt, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	epochCoverage := uint64(types.TxNonceToMsgEpochCoverage(txNonce))
	return (*hexutil.Uint64)(&epochCoverage), nil
}

type expireInfoResult struct {
	ExistCurrent        bool            `json:"existCurrent"`
	ExistCheckpoint     bool            `json:"existCheckpoint"`
	MaxExistBlockNumber *hexutil.Uint64 `json:"maxExistBlockNumber"`
}

// EstimatedExpiration returns the epoch coverage of the given address has sent for the given block number
func (api *OverAPI) ExpireInfo(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*expireInfoResult, error) {
	var results expireInfoResult
	header, err := api.b.HeaderByNumberOrHash(ctx, blockNrOrHash)
	if err != nil || header == nil {
		return nil, err
	}
	bn := header.Number.Uint64()
	epoch, err := api.b.CalcEpoch(bn)
	if err != nil {
		return nil, err
	}
	latestCkptNumber, exist := api.b.ChainConfig().CalcLastCheckpointBlockNumberByNumber(bn)
	if exist {
		ckptState, _, err := api.b.StateAndHeaderByNumber(ctx, rpc.BlockNumber(latestCkptNumber), true)
		if ckptState == nil || err != nil {
			return nil, err
		}
		if ckptState.Exist(address) {
			results.ExistCheckpoint = true
			maxExistBlockNumber := api.b.ChainConfig().CalcNextCheckpointBlockNumber(epoch)
			results.MaxExistBlockNumber = (*hexutil.Uint64)(&maxExistBlockNumber)
		}
	}

	state, _, err := api.b.StateAndHeaderByNumber(ctx, rpc.BlockNumber(bn), true)
	if state == nil || err != nil {
		return nil, err
	}
	if state.Exist(address) {
		results.ExistCurrent = true
		maxExistBlockNumber := api.b.ChainConfig().CalcNextCheckpointBlockNumber(epoch + 1)
		results.MaxExistBlockNumber = (*hexutil.Uint64)(&maxExistBlockNumber)
	}
	return &results, nil
}
