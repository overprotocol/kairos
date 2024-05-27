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

package main

import (
	"flag"
	"math/big"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	DefaultPort          = ":32311"                 // Default TCP port for the server
	DefaultMinimumReward = big.NewInt(params.Ether) // Default minimum reward for sending restoration transaction
)

var (
	portFlag           = flag.String("port", DefaultPort, "Server listening port")
	corsDomainFlag     = flag.String("corsdomain", "*", "Comma separated list of domains from which to accept cross origin requests (browser enforced)")
	rpcFlag            = flag.String("rpc", "", "The rpc endpoint of a local or remote geth node")
	ipcFlag            = flag.String("ipc", "", "The ipc endpoint of a local geth node")
	signerFlag         = flag.String("signer", "", "Signer address for signing restoration transaction and receiving reward")
	keystoreDirFlag    = flag.String("keystore", filepath.Join(node.DefaultDataDir(), "keystore"), "Directory for the keystore")
	minimumRewardFlag  = flag.String("minimum-reward", DefaultMinimumReward.String(), "Minimum reward for sending restoration transaction")
	passphraseFileFlag = flag.String("passphrase", "", "Passphrase file for unlocking signer account")
)

func main() {
	flag.Parse()
	var client *rpc.Client
	if *ipcFlag != "" {
		client = newIPCClient(*ipcFlag)
	} else if *rpcFlag != "" {
		client = newRPCClient(*rpcFlag)
	} else {
		utils.Fatalf("Either ipc or rpc flag must be set")
	}
	if *signerFlag == "" {
		utils.Fatalf("Signer flag must be set")
	}

	ks := keystore.NewKeyStore(*keystoreDirFlag, keystore.StandardScryptN, keystore.StandardScryptP)
	passphrase := getPassphrase(*passphraseFileFlag)
	am := accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: false}, ks)
	wallet, err := am.Find(accounts.Account{Address: common.HexToAddress(*signerFlag)})
	if wallet == nil || err != nil {
		utils.Fatalf("Failed to find signer account: %v", err)
	}
	err = ks.Unlock(accounts.Account{
		Address: common.HexToAddress(*signerFlag),
	}, passphrase)
	if err != nil {
		utils.Fatalf("Failed to unlock signer account: %v", err)
	}
	minimumReward, success := new(big.Int).SetString(*minimumRewardFlag, 10)
	if !success {
		utils.Fatalf("Failed to parse minimum reward: %v", err)
	}
	restoreHandler := NewHandler(client, common.HexToAddress(*signerFlag), wallet.SignTx, minimumReward)
	server := NewServer(restoreHandler)
	server.start()
}
