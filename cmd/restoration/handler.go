package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

type SignerFn func(signer accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
type Handler struct {
	client     *rpc.Client
	ethclient  *ethclient.Client
	gethclient *gethclient.Client
	signer     common.Address
	signFn     SignerFn

	minimumReward *big.Int
	chainId       *big.Int

	lock sync.Mutex
}

func NewHandler(client *rpc.Client, signer common.Address, signFn SignerFn, minimumReward *big.Int) *Handler {
	ethClient := ethclient.NewClient(client)
	chainId, err := ethClient.ChainID(context.Background())
	if err != nil {
		log.Fatalf("failed to get chainId: %v", err)
	}
	if chainId == nil {
		log.Fatalf("chainId is nil")
	}
	return &Handler{
		client:        client,
		ethclient:     ethClient,
		gethclient:    gethclient.New(client),
		signer:        signer,
		signFn:        signFn,
		minimumReward: minimumReward,
		chainId:       chainId,
	}
}

func (h *Handler) HandleRequestRestoration(ctx context.Context, restoreData *types.RestoreData) (string, error) {
	if err := h.checkRestoreData(ctx, restoreData); err != nil {
		return "", fmt.Errorf("failed to check restore data: %w", err)
	}
	restorationProof, err := h.getRestorationProof(ctx, restoreData)
	if err != nil {
		return "", fmt.Errorf("failed to get restoration proof: %w", err)
	}
	if err := h.checkFeePayable(ctx, restoreData, restorationProof.RestoredBalance); err != nil {
		return "", fmt.Errorf("failed to check fee payable: %w", err)
	}

	h.lock.Lock()
	defer h.lock.Unlock()
	tx, err := h.makeTransaction(ctx, restorationProof.Proof, restoreData)
	if err != nil {
		return "", fmt.Errorf("failed to make transaction: %w", err)
	}
	if err := checkProfitable(tx.Gas(), tx.GasFeeCap(), restoreData.Fee, h.minimumReward); err != nil {
		return "", fmt.Errorf("failed to check profitable: %w", err)
	}
	signedTx, err := h.signFn(accounts.Account{Address: h.signer}, tx, h.chainId)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}
	err = h.sendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}
	return signedTx.Hash().Hex(), nil
}

func (h *Handler) HandleMinimumFee() string {
	return h.minimumReward.String()
}

func (h *Handler) HandleFeeRecipient() string {
	return h.signer.Hex()
}

func (h *Handler) checkRestoreData(ctx context.Context, restoreData *types.RestoreData) error {
	if restoreData.ChainID != h.chainId {
		return fmt.Errorf("chain ID mismatch")
	}
	if restoreData.FeeRecipient == nil || *restoreData.FeeRecipient != h.signer {
		return fmt.Errorf("fee recipient must be %s", h.signer.Hex())
	}
	if restoreData.SourceEpoch <= restoreData.TargetEpoch {
		return fmt.Errorf("target epoch must be prior to source epoch")
	}
	epochCoverage, err := h.getEpochCoverage(ctx, restoreData.Target)
	if err != nil {
		return fmt.Errorf("failed to get epoch coverage: %w", err)
	}
	if epochCoverage != restoreData.SourceEpoch {
		return fmt.Errorf("source epoch should be same as the current epoch coverage")
	}
	return nil
}

func (h *Handler) getEpochCoverage(ctx context.Context, target common.Address) (uint32, error) {
	nonce, err := h.ethclient.NonceAt(ctx, target, nil)
	if err != nil {
		return 0, err
	}
	return types.TxNonceToMsgEpochCoverage(nonce), nil
}

func (h *Handler) getRestorationProof(ctx context.Context, restoreData *types.RestoreData) (*gethclient.RestorationProofResult, error) {
	return h.gethclient.GetRestorationProof(ctx, restoreData.Target, restoreData.TargetEpoch)
}

func (h *Handler) checkFeePayable(ctx context.Context, restoreData *types.RestoreData, restoredBalance *big.Int) error {
	restoreDataSigner := types.LatestRestoreDataSigner(&params.ChainConfig{ChainID: h.chainId})
	sender, err := restoreDataSigner.Sender(restoreData)
	if err != nil {
		return fmt.Errorf("wrong signature: %w", err)
	}
	senderBalance, err := h.ethclient.BalanceAt(ctx, sender, nil)
	if err != nil {
		return fmt.Errorf("failed to get sender balance: %w", err)
	}
	if senderBalance.Cmp(restoreData.Fee) < 0 {
		if sender == restoreData.Target {
			if new(big.Int).Add(senderBalance, restoredBalance).Cmp(restoreData.Fee) < 0 {
				return fmt.Errorf("sender balance is not enough")
			}
		} else {
			return fmt.Errorf("sender balance is not enough")
		}
	}
	return nil
}

func (h *Handler) makeTransaction(ctx context.Context, proof []byte, restoreData *types.RestoreData) (*types.Transaction, error) {
	estimatedGas, err := h.ethclient.EstimateGas(ctx, ethereum.CallMsg{
		From:        h.signer,
		To:          nil,
		Gas:         0,
		Value:       big.NewInt(0),
		Data:        proof,
		RestoreData: restoreData,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to estimate gas: %w", err)
	}
	header, err := h.ethclient.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get header: %w", err)
	}
	gasTipCap, err := h.ethclient.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas tip cap: %w", err)
	}
	gasFeeCap := new(big.Int).Add(gasTipCap, new(big.Int).Mul(header.BaseFee, big.NewInt(2)))
	nonce, err := h.ethclient.PendingNonceAt(ctx, h.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}
	tx := types.NewTx(&types.RestorationTx{
		ChainID:     h.chainId,
		Nonce:       nonce,
		GasTipCap:   gasTipCap,
		GasFeeCap:   gasFeeCap,
		Gas:         estimatedGas,
		To:          nil,
		Value:       common.Big0,
		Data:        proof,
		RestoreData: restoreData,
	})
	return tx, nil
}

func (h *Handler) sendTransaction(ctx context.Context, tx *types.Transaction) error {
	return h.ethclient.SendTransaction(ctx, tx)
}

func checkProfitable(estimatedGas uint64, gasFeeCap, fee, minimumReward *big.Int) error {
	estimatedGasExpense := new(big.Int).Mul(gasFeeCap, big.NewInt(int64(estimatedGas)))
	if new(big.Int).Sub(fee, estimatedGasExpense).Cmp(minimumReward) < 0 {
		return fmt.Errorf("reward is not enough")
	}
	return nil
}
