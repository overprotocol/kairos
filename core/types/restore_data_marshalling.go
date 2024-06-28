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
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type restoreDataJSON struct {
	ChainID      *hexutil.Big    `json:"chainId,omitempty"`
	Target       *common.Address `json:"target"`
	SourceEpoch  *hexutil.Uint64 `json:"sourceEpoch"`
	TargetEpoch  *hexutil.Uint64 `json:"targetEpoch"`
	Fee          *hexutil.Big    `json:"fee"`
	FeeRecipient *common.Address `json:"feeRecipient"`
	V            *hexutil.Big    `json:"v"`
	R            *hexutil.Big    `json:"r"`
	S            *hexutil.Big    `json:"s"`
}

// MarshalJSON marshals as JSON.
func (rd *RestoreData) MarshalJSON() ([]byte, error) {
	sourceEpoch := uint64(rd.SourceEpoch)
	targetEpoch := uint64(rd.TargetEpoch)
	enc := restoreDataJSON{
		ChainID:      (*hexutil.Big)(rd.ChainID),
		Target:       &rd.Target,
		SourceEpoch:  (*hexutil.Uint64)(&sourceEpoch),
		TargetEpoch:  (*hexutil.Uint64)(&targetEpoch),
		Fee:          (*hexutil.Big)(rd.Fee),
		FeeRecipient: rd.FeeRecipient,
		V:            (*hexutil.Big)(rd.V),
		R:            (*hexutil.Big)(rd.R),
		S:            (*hexutil.Big)(rd.S),
	}
	return json.Marshal(enc)
}

// UnmarshalJSON unmarshals from JSON.
func (rd *RestoreData) UnmarshalJSON(input []byte) error {
	var dec restoreDataJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.ChainID == nil {
		return errors.New("missing required field 'chainId' in restore data")
	}
	rd.ChainID = (*big.Int)(dec.ChainID)
	if dec.Target == nil {
		return errors.New("missing required field 'target' in restore data")
	}
	rd.Target = *dec.Target
	if dec.SourceEpoch == nil {
		return errors.New("missing required field 'sourceEpoch' in restore data")
	}
	rd.SourceEpoch = uint32(*dec.SourceEpoch)
	if dec.TargetEpoch == nil {
		return errors.New("missing required field 'targetEpoch' in restore data")
	}
	rd.TargetEpoch = uint32(*dec.TargetEpoch)
	if dec.Fee != nil {
		rd.Fee = (*big.Int)(dec.Fee)
	}
	if dec.FeeRecipient != nil {
		rd.FeeRecipient = dec.FeeRecipient
	}
	if dec.V == nil {
		return errors.New("missing required field 'v' in restore data")
	}
	rd.V = (*big.Int)(dec.V)
	if dec.R == nil {
		return errors.New("missing required field 'r' in restore data")
	}
	rd.R = (*big.Int)(dec.R)
	if dec.S == nil {
		return errors.New("missing required field 's' in restore data")
	}
	rd.S = (*big.Int)(dec.S)
	if rd.V.Sign() != 0 || rd.R.Sign() != 0 || rd.S.Sign() != 0 {
		if err := sanityCheckSignature(rd.V, rd.R, rd.S, false); err != nil {
			return err
		}
	}
	return nil
}
