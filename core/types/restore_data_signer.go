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
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var ErrNilSignRestoreData = errors.New("nil sign from RestoreData")

func LatestRestoreDataSigner(config *params.ChainConfig) RestoreDataSigner {
	return NewAlpacaRestoreDataSigner(config.ChainID)
}

// RestoreDataSigner encapsulates restore data signature handling. The name of this
// type is slightly misleading because Signers don't actually sign, they're just
// for validating and processing of signatures.
type RestoreDataSigner interface {
	// Sender returns the sender address of the restore data.
	Sender(rd *RestoreData) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(rd *RestoreData, sig []byte) (r, s, v *big.Int, err error)
	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the restore data hash that is signed by the
	// private key. This hash does not uniquely identify the restore data.
	Hash(rd *RestoreData) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
}

type alpacaRestoreDataSigner struct {
	chainId, chainIdMul *big.Int
}

// NewAlpacaRestoreDataSigner returns a signer that accepts restore data.
func NewAlpacaRestoreDataSigner(chainId *big.Int) RestoreDataSigner {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return alpacaRestoreDataSigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

// SignRestoreData signs the restore data using the given restoreDataSigner and private key.
func SignRestoreData(rd *RestoreData, s RestoreDataSigner, prv *ecdsa.PrivateKey) (*RestoreData, error) {
	h := s.Hash(rd)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return rd.WithSignature(s, sig)
}

func (s alpacaRestoreDataSigner) ChainID() *big.Int {
	return s.chainId
}

func (s alpacaRestoreDataSigner) Sender(rd *RestoreData) (common.Address, error) {
	if rd.V == nil || rd.R == nil || rd.S == nil {
		return common.Address{}, ErrNilSignRestoreData
	}
	V, R, S := rd.V, rd.R, rd.S
	// Restoration data are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	V = new(big.Int).Add(V, big.NewInt(27))
	if rd.ChainID.Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, rd.ChainID, s.chainId)
	}
	return recoverPlain(s.Hash(rd), R, S, V, true)
}

func (s alpacaRestoreDataSigner) Equal(s2 Signer) bool {
	x, ok := s2.(alpacaSigner)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s alpacaRestoreDataSigner) SignatureValues(rd *RestoreData, sig []byte) (R, S, V *big.Int, err error) {
	// Check that chain ID of the restore data matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the restore data.
	if rd.ChainID.Sign() != 0 && rd.ChainID.Cmp(s.chainId) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, rd.ChainID, s.chainId)
	}
	R, S, _ = decodeSignature(sig)
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the restore data.
func (s alpacaRestoreDataSigner) Hash(rd *RestoreData) common.Hash {
	return rlpHash([]interface{}{
		rd.ChainID,
		rd.Target,
		rd.SourceEpoch,
		rd.TargetEpoch,
		rd.Fee,
		rd.FeeRecipient,
	})
}
