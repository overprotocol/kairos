package main

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// RestoreDataArgs represents the arguments to construct a restore data
type RestoreDataArgs struct {
	ChainID      *hexutil.Big    `json:"chainId"`
	Target       common.Address  `json:"target"`
	SourceEpoch  hexutil.Uint64  `json:"sourceEpoch"`
	TargetEpoch  hexutil.Uint64  `json:"targetEpoch"`
	Fee          *hexutil.Big    `json:"fee"`
	FeeRecipient *common.Address `json:"feeRecipient"` // nil means not paying a fee
	V            *hexutil.Big    `json:"v"`
	R            *hexutil.Big    `json:"r"`
	S            *hexutil.Big    `json:"s"`
}

func (args *RestoreDataArgs) toRestoreData() *types.RestoreData {
	return types.NewRestoreDataWithSignature(
		(*big.Int)(args.ChainID),
		args.Target,
		uint32(args.SourceEpoch),
		uint32(args.TargetEpoch),
		(*big.Int)(args.Fee),
		args.FeeRecipient,
		(*big.Int)(args.V),
		(*big.Int)(args.R),
		(*big.Int)(args.S),
	)
}
