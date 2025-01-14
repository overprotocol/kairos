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

package forkid

import (
	"bytes"
	"hash/crc32"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// TestCreation tests that different genesis and fork rule combinations result in
// the correct fork ID.
func TestCreation(t *testing.T) {
	type testcase struct {
		head uint64
		time uint64
		want ID
	}
	tests := []struct {
		config  *params.ChainConfig
		genesis *types.Block
		cases   []testcase
	}{
		// Mainnet test cases
		{
			params.MainnetChainConfig,
			core.DefaultGenesisBlock().ToBlock(),
			[]testcase{
				{0, 0, ID{Hash: checksumToBytes(0xcf2b60e5), Next: 0}},          // Unsynced, last Frontier, Homestead, Tangerine, Spurious, Byzantium, Constantinople, Petersburg, Istanbul, Berlin and London block
				{0, 1733529600, ID{Hash: checksumToBytes(0xcf2b60e5), Next: 0}}, // Shanghai, Cancun, Prague
			},
		},
		// Dolphin test cases
		{
			params.DolphinChainConfig,
			core.DefaultDolphinGenesisBlock().ToBlock(),
			[]testcase{
				{0, 0, ID{Hash: checksumToBytes(0xc8c3ebb9), Next: 0}},          // Unsynced, last Frontier, Homestead, Tangerine, Spurious, Byzantium, Constantinople, Petersburg, Istanbul, Berlin and London block
				{0, 1733296014, ID{Hash: checksumToBytes(0xc8c3ebb9), Next: 0}}, // Shanghai, Cancun, Prague
			},
		},
	}
	for i, tt := range tests {
		for j, ttt := range tt.cases {
			if have := NewID(tt.config, tt.genesis, ttt.head, ttt.time); have != ttt.want {
				t.Errorf("test %d, case %d: fork ID mismatch: have %x, want %x", i, j, have, ttt.want)
			}
		}
	}
}

// TestValidation tests that a local peer correctly validates and accepts a remote
// fork ID.
func TestValidation(t *testing.T) {
	// Config that has not timestamp enabled
	legacyConfig := *params.MainnetChainConfig
	legacyConfig.ShanghaiTime = nil
	legacyConfig.CancunTime = nil

	tests := []struct {
		config *params.ChainConfig
		head   uint64
		time   uint64
		id     ID
		err    error
	}{
		//------------------
		// Block based tests
		//------------------

		// Local is Prague Gray Glacier, remote announces the same. No future fork is announced.
		{&legacyConfig, 0, 0, ID{Hash: checksumToBytes(0xcf2b60e5), Next: 0}, nil},

		// // Local is mainnet Gray Glacier, remote announces the same. Remote also announces a next fork
		// // at block 0xffffffff, but that is uncertain.
		{&legacyConfig, 0, 0, ID{Hash: checksumToBytes(0xcf2b60e5), Next: math.MaxUint64}, nil},

		// //------------------------------------
		// // Block to timestamp transition tests
		// //------------------------------------

		// // Local is mainnet currently in Gray Glacier only (so it's aware of Shanghai), remote announces
		// // also Gray Glacier, but it's not yet aware of Shanghai (e.g. non updated node before the fork).
		// // In this case we don't know if Shanghai passed yet or not.
		{params.MainnetChainConfig, 0, 0, ID{Hash: checksumToBytes(0xcf2b60e5), Next: 0}, nil},

		// // Local is mainnet currently in Gray Glacier only (so it's aware of Shanghai), remote announces
		// // also Gray Glacier, and it's also aware of Shanghai (e.g. updated node before the fork). We
		// // don't know if Shanghai passed yet (will pass) or not.
		{params.MainnetChainConfig, 0, 1733529600, ID{Hash: checksumToBytes(0xcf2b60e5), Next: 0}, nil},

		// // Local is mainnet currently in Gray Glacier only (so it's aware of Shanghai), remote announces
		// // also Gray Glacier, and it's also aware of some random fork (e.g. misconfigured Shanghai). As
		// // neither forks passed at neither nodes, they may mismatch, but we still connect for now.
		{params.MainnetChainConfig, 0, 1733529600, ID{Hash: checksumToBytes(0xcf2b60e5), Next: math.MaxUint64}, nil},

		// // Local is mainnet Shanghai, remote is random Shanghai.
		{params.MainnetChainConfig, 0, 1733529600, ID{Hash: checksumToBytes(0x12345678), Next: 0}, ErrLocalIncompatibleOrStale},

		// // Local is mainnet Cancun, far in the future. Remote announces Gopherium (non existing fork)
		// // at some future timestamp 8888888888, for itself, but past block for local. Local is incompatible.
		// //
		// // This case detects non-upgraded nodes with majority hash power (typical Ropsten mess).
		{params.MainnetChainConfig, 88888888, 8888888888, ID{Hash: checksumToBytes(0x9f3d2254), Next: 8888888888}, ErrLocalIncompatibleOrStale},

		// // Local is mainnet Shanghai. Remote is also in Shanghai, but announces Gopherium (non existing
		// // fork) at timestamp 1668000000, before Cancun. Local is incompatible.
		{params.MainnetChainConfig, 20999999, 1699999999, ID{Hash: checksumToBytes(0x71147644), Next: 1700000000}, ErrLocalIncompatibleOrStale},

		// Local is mainnet Alpaca, Remote is mainnet Alpaca
		{params.MainnetChainConfig, 0, 0, ID{Hash: checksumToBytes(0xcf2b60e5), Next: 0}, nil},
	}
	genesis := core.DefaultGenesisBlock().ToBlock()
	for i, tt := range tests {
		filter := newFilter(tt.config, genesis, func() (uint64, uint64) { return tt.head, tt.time })
		if err := filter(tt.id); err != tt.err {
			t.Errorf("test %d: validation error mismatch: have %v, want %v", i, err, tt.err)
		}
	}
}

// Tests that IDs are properly RLP encoded (specifically important because we
// use uint32 to store the hash, but we need to encode it as [4]byte).
func TestEncoding(t *testing.T) {
	tests := []struct {
		id   ID
		want []byte
	}{
		{ID{Hash: checksumToBytes(0), Next: 0}, common.Hex2Bytes("c6840000000080")},
		{ID{Hash: checksumToBytes(0xdeadbeef), Next: 0xBADDCAFE}, common.Hex2Bytes("ca84deadbeef84baddcafe,")},
		{ID{Hash: checksumToBytes(math.MaxUint32), Next: math.MaxUint64}, common.Hex2Bytes("ce84ffffffff88ffffffffffffffff")},
	}
	for i, tt := range tests {
		have, err := rlp.EncodeToBytes(tt.id)
		if err != nil {
			t.Errorf("test %d: failed to encode forkid: %v", i, err)
			continue
		}
		if !bytes.Equal(have, tt.want) {
			t.Errorf("test %d: RLP mismatch: have %x, want %x", i, have, tt.want)
		}
	}
}

// Tests that time-based forks which are active at genesis are not included in
// forkid hash.
func TestTimeBasedForkInGenesis(t *testing.T) {
	var (
		time       = uint64(1690475657)
		genesis    = types.NewBlockWithHeader(&types.Header{Time: time})
		forkidHash = checksumToBytes(crc32.ChecksumIEEE(genesis.Hash().Bytes()))
		config     = func(shanghai, cancun uint64) *params.ChainConfig {
			return &params.ChainConfig{
				ChainID:                 big.NewInt(1337),
				HomesteadBlock:          big.NewInt(0),
				DAOForkBlock:            nil,
				DAOForkSupport:          true,
				EIP150Block:             big.NewInt(0),
				EIP155Block:             big.NewInt(0),
				EIP158Block:             big.NewInt(0),
				ByzantiumBlock:          big.NewInt(0),
				ConstantinopleBlock:     big.NewInt(0),
				PetersburgBlock:         big.NewInt(0),
				IstanbulBlock:           big.NewInt(0),
				MuirGlacierBlock:        big.NewInt(0),
				BerlinBlock:             big.NewInt(0),
				LondonBlock:             big.NewInt(0),
				TerminalTotalDifficulty: big.NewInt(0),
				MergeNetsplitBlock:      big.NewInt(0),
				ShanghaiTime:            &shanghai,
				CancunTime:              &cancun,
				Ethash:                  new(params.EthashConfig),
			}
		}
	)
	tests := []struct {
		config *params.ChainConfig
		want   ID
	}{
		// Shanghai active before genesis, skip
		{config(time-1, time+1), ID{Hash: forkidHash, Next: time + 1}},

		// Shanghai active at genesis, skip
		{config(time, time+1), ID{Hash: forkidHash, Next: time + 1}},

		// Shanghai not active, skip
		{config(time+1, time+2), ID{Hash: forkidHash, Next: time + 1}},
	}
	for _, tt := range tests {
		if have := NewID(tt.config, genesis, 0, time); have != tt.want {
			t.Fatalf("incorrect forkid hash: have %x, want %x", have, tt.want)
		}
	}
}
