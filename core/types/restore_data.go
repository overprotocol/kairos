// Copyright 2024 The kairos Authors
// This file is part of the kairos library.
//
// The kairos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The kairos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the kairos library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// RestoreData represents the data that is needed to restore an account.
type RestoreData struct {
	ChainID      *big.Int        `json:"chainId" gencodec:"required"`
	Target       common.Address  `json:"target" gencodec:"required"`
	SourceEpoch  uint32          `json:"sourceEpoch" gencodec:"required"`
	TargetEpoch  uint32          `json:"targetEpoch" gencodec:"required"`
	Fee          *big.Int        `json:"fee" gencodec:"required"`
	FeeRecipient *common.Address `json:"feeRecipient" rlp:"nil"` // nil means not paying a fee
	V            *big.Int        `json:"v" gencodec:"required"`
	R            *big.Int        `json:"r" gencodec:"required"`
	S            *big.Int        `json:"s" gencodec:"required"`
}

func NewRestoreData(chainID *big.Int, target common.Address, sourceEpoch, targetEpoch uint32, fee *big.Int, feeRecipient *common.Address) *RestoreData {
	restoreData := &RestoreData{
		ChainID:      new(big.Int),
		Target:       common.BytesToAddress(target.Bytes()),
		SourceEpoch:  sourceEpoch,
		TargetEpoch:  targetEpoch,
		Fee:          new(big.Int),
		FeeRecipient: copyAddressPtr(feeRecipient),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if chainID != nil {
		restoreData.ChainID.Set(chainID)
	}
	if fee != nil {
		restoreData.Fee.Set(fee)
	}
	return restoreData
}

func NewRestoreDataWithSignature(chainID *big.Int, target common.Address, sourceEpoch, targetEpoch uint32, fee *big.Int, feeRecipient *common.Address, V, R, S *big.Int) *RestoreData {
	restoreData := NewRestoreData(chainID, target, sourceEpoch, targetEpoch, fee, feeRecipient)
	if V != nil {
		restoreData.V.Set(V)
	}
	if R != nil {
		restoreData.R.Set(R)
	}
	if S != nil {
		restoreData.S.Set(S)
	}
	return restoreData
}

// copy creates a deep copy and initializes all fields
func (data *RestoreData) copy() *RestoreData {
	cpy := &RestoreData{
		ChainID:      new(big.Int),
		Target:       common.BytesToAddress(data.Target.Bytes()),
		SourceEpoch:  data.SourceEpoch,
		TargetEpoch:  data.TargetEpoch,
		Fee:          new(big.Int),
		FeeRecipient: copyAddressPtr(data.FeeRecipient),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if data.ChainID != nil {
		cpy.ChainID.Set(data.ChainID)
	}
	if data.Fee != nil {
		cpy.Fee.Set(data.Fee)
	}
	if data.V != nil {
		cpy.V.Set(data.V)
	}
	if data.R != nil {
		cpy.R.Set(data.R)
	}
	if data.S != nil {
		cpy.S.Set(data.S)
	}
	return cpy
}

// Hash returns the data hash.
func (data *RestoreData) Hash() common.Hash {
	return rlpHash(data)
}

// WithSignature returns a new restored data with the given signature.
// This signature needs to be in the [R || S || V] format where V is 0 or 1.
func (data *RestoreData) WithSignature(signer RestoreDataSigner, sig []byte) (*RestoreData, error) {
	r, s, v, err := signer.SignatureValues(data, sig)
	if err != nil {
		return nil, err
	}
	cpy := data.copy()
	cpy.ChainID.Set(signer.ChainID())
	cpy.V.Set(v)
	cpy.R.Set(r)
	cpy.S.Set(s)
	return cpy, nil
}
