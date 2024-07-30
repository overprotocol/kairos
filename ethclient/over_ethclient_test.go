// Copyright 2016 The go-ethereum Authors
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

package ethclient

import (
	"context"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

const (
	testEpoch = 200
)

var (
	overGenesis = &core.Genesis{
		Config:    params.TestChainConfig.SetTestSweepEpoch(testEpoch),
		Alloc:     core.GenesisAlloc{testAddr: {Balance: testBalance}},
		ExtraData: []byte("test genesis"),
		Timestamp: 9000,
		BaseFee:   big.NewInt(params.InitialBaseFee),
	}
)

var (
	testKey2, _     = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	testAddr2       = crypto.PubkeyToAddress(testKey2.PublicKey)
	balanceAtEpoch2 *big.Int
	balanceAtEpoch3 *big.Int
)

func newOverTestBackend(t *testing.T) (*node.Node, []*types.Block) {
	// Generate test chain.
	blocks := generateOverTestChain()

	// Create node
	n, err := node.New(&node.Config{})
	if err != nil {
		t.Fatalf("can't create new node: %v", err)
	}
	// Create Ethereum Service
	config := &ethconfig.Config{Genesis: overGenesis}
	ethservice, err := eth.New(n, config)
	if err != nil {
		t.Fatalf("can't create new ethereum service: %v", err)
	}
	// Import the test chain.
	if err := n.Start(); err != nil {
		t.Fatalf("can't start test node: %v", err)
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks[1:]); err != nil {
		t.Fatalf("can't import test blocks: %v", err)
	}
	return n, blocks
}

func generateOverTestChain() []*types.Block {
	generate := func(i int, g *core.BlockGen) {
		if g.Number().Uint64() == 2*testEpoch-1 {
			g.AddTx(
				types.MustSignNewTx(testKey, types.LatestSigner(overGenesis.Config), &types.LegacyTx{
					Nonce:    types.MsgToTxNonce(0, 0),
					Value:    big.NewInt(12),
					GasPrice: big.NewInt(params.InitialBaseFee),
					Gas:      params.TxGas,
					To:       &common.Address{2},
				}),
			)
		} else if g.Number().Uint64() == 3*testEpoch-1 {
			g.AddTx(
				types.MustSignNewTx(testKey, types.LatestSigner(overGenesis.Config), &types.LegacyTx{
					Nonce:    types.MsgToTxNonce(0, 1),
					Value:    big.NewInt(1e15),
					GasPrice: big.NewInt(params.InitialBaseFee),
					Gas:      params.TxGas,
					To:       &testAddr2,
				}),
			)
			balanceAtEpoch2 = big.NewInt(1e15)
		} else if g.Number().Uint64() == 4*testEpoch-1 {
			g.AddTx(
				types.MustSignNewTx(testKey2, types.LatestSigner(overGenesis.Config), &types.LegacyTx{
					Nonce:    types.MsgToTxNonce(1, 0),
					Value:    big.NewInt(0),
					GasPrice: big.NewInt(params.InitialBaseFee),
					Gas:      params.TxGas,
					To:       &common.Address{2},
				}),
			)
			balanceAtEpoch3 = new(big.Int).Sub(balanceAtEpoch2, big.NewInt(int64(params.TxGas*params.InitialBaseFee)))
		}
	}
	_, blocks, _ := core.GenerateChainWithGenesis(overGenesis, ethash.NewFaker(), 5*testEpoch, generate)
	return append([]*types.Block{overGenesis.ToBlock()}, blocks...)
}

func TestOverEthClient(t *testing.T) {
	backend, _ := newOverTestBackend(t)
	client := backend.Attach()
	defer backend.Close()
	defer client.Close()

	tests := map[string]struct {
		test func(t *testing.T)
	}{
		"SweepEpoch": {
			func(t *testing.T) { testSweepEpoch(t, client) },
		},
		"NextCheckpointBlockNumber": {
			func(t *testing.T) { testNextCheckpointBlockNumber(t, client) },
		},
		"EpochAt": {
			func(t *testing.T) { testEpochAt(t, client) },
		},
		"BalanceAtOver": {
			func(t *testing.T) { testBalanceAtOver(t, client) },
		},
		"ExistAtOver": {
			func(t *testing.T) { testExistAtOver(t, client) },
		},
		"TransactionCountAt": {
			func(t *testing.T) { testTransactionCountAt(t, client) },
		},
		"NonceAtOver": {
			func(t *testing.T) { testNonceAtOver(t, client) },
		},
		"EpochCoverageAt": {
			func(t *testing.T) { testEpochCoverageAt(t, client) },
		},
		"ExpireInfo": {
			func(t *testing.T) { testExpireInfo(t, client) },
		},
	}

	t.Parallel()
	for name, tt := range tests {
		t.Run(name, tt.test)
	}
}

func testSweepEpoch(t *testing.T, client *rpc.Client) {
	ec := NewClient(client)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	got, err := ec.SweepEpoch(ctx)
	if err != nil {
		t.Fatalf("SweepEpoch failed: %v", err)
	}
	if got != uint64(testEpoch) {
		t.Fatalf("SweepEpoch returned wrong result: got %v, want testEpoch", got)
	}
}

func testNextCheckpointBlockNumber(t *testing.T, client *rpc.Client) {
	ec := NewClient(client)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	got, err := ec.NextCheckpointBlockNumber(ctx, big.NewInt(-1))
	if err != nil {
		t.Fatalf("NextCheckpointBlockNumber failed: %v", err)
	}
	if got != 6*testEpoch-1 {
		t.Fatalf("NextCheckpointBlockNumber returned wrong result: got %v, want %v", got, 6*testEpoch-1)
	}
}

func testEpochAt(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		block   *big.Int
		want    uint32
		wantErr error
	}{
		"checkpoint block": {
			block: big.NewInt(testEpoch - 1),
			want:  0,
		},
		"first block of epoch": {
			block: big.NewInt(testEpoch),
			want:  1,
		},
		"middle of the epoch": {
			block: big.NewInt(2*testEpoch + testEpoch/2),
			want:  2,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.EpochAt(ctx, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("EpochAt(%v) error = %q, want %q", tt.block, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("EpochAt(%v) = %v, want %v", tt.block, got, tt.want)
			}
		})
	}
}

func testBalanceAtOver(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		account     common.Address
		withoutCkpt bool
		block       *big.Int
		want        *big.Int
		wantErr     error
	}{
		"epoch 0 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(testEpoch - 1),
			want:        common.Big0,
		},
		"epoch 1 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(2*testEpoch - 1),
			want:        common.Big0,
		},
		"epoch 2 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(3*testEpoch - 1),
			want:        balanceAtEpoch2,
		},
		"epoch 3 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(4*testEpoch - 1),
			want:        balanceAtEpoch3,
		},
		"epoch 4 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(5*testEpoch - 1),
			want:        common.Big0,
		},
		"epoch 0 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(testEpoch - 1),
			want:        common.Big0,
		},
		"epoch 1 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(2*testEpoch - 1),
			want:        common.Big0,
		},
		"epoch 2 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(3*testEpoch - 1),
			want:        balanceAtEpoch2,
		},
		"epoch 3 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(4*testEpoch - 1),
			want:        balanceAtEpoch3,
		},
		"epoch 4 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(5*testEpoch - 1),
			want:        balanceAtEpoch3,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.BalanceAtOver(ctx, tt.account, tt.withoutCkpt, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("BalanceAtOver(%x, %v) error = %q, want %q", tt.account, tt.block, err, tt.wantErr)
			}
			if got.Cmp(tt.want) != 0 {
				t.Fatalf("BalanceAtOver(%x, %v) = %v, want %v", tt.account, tt.block, got, tt.want)
			}
		})
	}
}

func testExistAtOver(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		account     common.Address
		withoutCkpt bool
		block       *big.Int
		want        bool
		wantErr     error
	}{
		"epoch 0 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(testEpoch - 1),
			want:        false,
		},
		"epoch 1 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(2*testEpoch - 1),
			want:        false,
		},
		"epoch 2 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(3*testEpoch - 1),
			want:        true,
		},
		"epoch 3 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(4*testEpoch - 1),
			want:        true,
		},
		"epoch 4 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(5*testEpoch - 1),
			want:        false,
		},
		"epoch 0 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(testEpoch - 1),
			want:        false,
		},
		"epoch 1 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(2*testEpoch - 1),
			want:        false,
		},
		"epoch 2 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(3*testEpoch - 1),
			want:        true,
		},
		"epoch 3 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(4*testEpoch - 1),
			want:        true,
		},
		"epoch 4 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(5*testEpoch - 1),
			want:        true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.ExistAtOver(ctx, tt.account, tt.withoutCkpt, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("ExistAtOver(%x, %v) error = %q, want %q", tt.account, tt.block, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ExistAtOver(%x, %v) = %v, want %v", tt.account, tt.block, got, tt.want)
			}
		})
	}
}

func testTransactionCountAt(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		account     common.Address
		withoutCkpt bool
		block       *big.Int
		want        uint64
		wantErr     error
	}{
		"epoch 0 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(testEpoch - 1),
			want:        0,
		},
		"epoch 1 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(2*testEpoch - 1),
			want:        0,
		},
		"epoch 2 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(3*testEpoch - 1),
			want:        types.MsgToTxNonce(1, 0),
		},
		"epoch 3 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(4*testEpoch - 1),
			want:        types.MsgToTxNonce(1, 1),
		},
		"epoch 4 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(5*testEpoch - 1),
			want:        types.MsgToTxNonce(3, 0),
		},
		"epoch 0 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(testEpoch - 1),
			want:        0,
		},
		"epoch 1 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(2*testEpoch - 1),
			want:        0,
		},
		"epoch 2 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(3*testEpoch - 1),
			want:        types.MsgToTxNonce(1, 0),
		},
		"epoch 3 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(4*testEpoch - 1),
			want:        types.MsgToTxNonce(1, 1),
		},
		"epoch 4 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(5*testEpoch - 1),
			want:        types.MsgToTxNonce(1, 1),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.TransactionCountAt(ctx, tt.account, tt.withoutCkpt, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("TransactionCountAt(%x, %v) error = %q, want %q", tt.account, tt.block, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("TransactionCountAt(%x, %v) = %v, want %v", tt.account, tt.block, got, tt.want)
			}
		})
	}
}

func testNonceAtOver(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		account     common.Address
		withoutCkpt bool
		block       *big.Int
		want        uint64
		wantErr     error
	}{
		"epoch 0 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(testEpoch - 1),
			want:        0,
		},
		"epoch 1 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(2*testEpoch - 1),
			want:        0,
		},
		"epoch 2 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(3*testEpoch - 1),
			want:        0,
		},
		"epoch 3 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(4*testEpoch - 1),
			want:        1,
		},
		"epoch 4 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(5*testEpoch - 1),
			want:        0,
		},
		"epoch 0 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(testEpoch - 1),
			want:        0,
		},
		"epoch 1 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(2*testEpoch - 1),
			want:        0,
		},
		"epoch 2 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(3*testEpoch - 1),
			want:        0,
		},
		"epoch 3 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(4*testEpoch - 1),
			want:        1,
		},
		"epoch 4 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(5*testEpoch - 1),
			want:        1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.NonceAtOver(ctx, tt.account, tt.withoutCkpt, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("testNonceAtOver(%x, %v) error = %q, want %q", tt.account, tt.block, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("testNonceAtOver(%x, %v) = %v, want %v", tt.account, tt.block, got, tt.want)
			}
		})
	}
}

func testEpochCoverageAt(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		account     common.Address
		withoutCkpt bool
		block       *big.Int
		want        uint64
		wantErr     error
	}{
		"epoch 0 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(testEpoch - 1),
			want:        0,
		},
		"epoch 1 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(2*testEpoch - 1),
			want:        0,
		},
		"epoch 2 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(3*testEpoch - 1),
			want:        1,
		},
		"epoch 3 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(4*testEpoch - 1),
			want:        1,
		},
		"epoch 4 without checkpoint": {
			account:     testAddr2,
			withoutCkpt: true,
			block:       big.NewInt(5*testEpoch - 1),
			want:        3,
		},
		"epoch 0 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(testEpoch - 1),
			want:        0,
		},
		"epoch 1 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(2*testEpoch - 1),
			want:        0,
		},
		"epoch 2 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(3*testEpoch - 1),
			want:        1,
		},
		"epoch 3 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(4*testEpoch - 1),
			want:        1,
		},
		"epoch 4 with checkpoint": {
			account:     testAddr2,
			withoutCkpt: false,
			block:       big.NewInt(5*testEpoch - 1),
			want:        1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.EpochCoverageAt(ctx, tt.account, tt.withoutCkpt, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("EpochCoverageAt(%x, %v) error = %q, want %q", tt.account, tt.block, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("EpochCoverageAt(%x, %v) = %v, want %v", tt.account, tt.block, got, tt.want)
			}
		})
	}
}

func testExpireInfo(t *testing.T, client *rpc.Client) {
	tests := map[string]struct {
		account common.Address
		block   *big.Int
		want    expireInfoResult
		wantErr error
	}{
		"epoch 0 without checkpoint": {
			account: testAddr2,
			block:   big.NewInt(testEpoch - 1),
			want: expireInfoResult{
				ExistCurrent:        false,
				ExistCheckpoint:     false,
				MaxExistBlockNumber: 0,
			},
		},
		"epoch 1 without checkpoint": {
			account: testAddr2,
			block:   big.NewInt(2*testEpoch - 1),
			want: expireInfoResult{
				ExistCurrent:        false,
				ExistCheckpoint:     false,
				MaxExistBlockNumber: 0,
			},
		},
		"epoch 2 without checkpoint": {
			account: testAddr2,
			block:   big.NewInt(3*testEpoch - 1),
			want: expireInfoResult{
				ExistCurrent:        true,
				ExistCheckpoint:     false,
				MaxExistBlockNumber: 4*testEpoch - 1,
			},
		},
		"epoch 3 without checkpoint": {
			account: testAddr2,
			block:   big.NewInt(4*testEpoch - 1),
			want: expireInfoResult{
				ExistCurrent:        true,
				ExistCheckpoint:     true,
				MaxExistBlockNumber: 5*testEpoch - 1,
			},
		},
		"epoch 4 without checkpoint": {
			account: testAddr2,
			block:   big.NewInt(5*testEpoch - 1),
			want: expireInfoResult{
				ExistCurrent:        false,
				ExistCheckpoint:     true,
				MaxExistBlockNumber: 5*testEpoch - 1,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ec := NewClient(client)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			got, err := ec.ExpireInfoAt(ctx, tt.account, tt.block)
			if tt.wantErr != nil && (err == nil || err.Error() != tt.wantErr.Error()) {
				t.Fatalf("ExpireInfoAt(%x, %v) error = %q, want %q", tt.account, tt.block, err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ExpireInfoAt(%x, %v) = %v, want %v", tt.account, tt.block, got, tt.want)
			}
		})
	}
}
