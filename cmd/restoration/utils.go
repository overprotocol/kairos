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
	"context"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/rpc"
)

// newRPCClient creates a rpc client with specified node URL.
func newRPCClient(url string) *rpc.Client {
	client, err := rpc.Dial(url)
	if err != nil {
		utils.Fatalf("Failed to connect to Ethereum node using rpc: %v", err)
	}
	return client
}

// newIPCClient creates a ipc client with specified path.
func newIPCClient(path string) *rpc.Client {
	client, err := rpc.DialIPC(context.Background(), path)
	if err != nil {
		utils.Fatalf("Failed to connect to Ethereum node using ipc: %v", err)
	}
	return client
}

func getPassphrase(passphraseFile string) string {
	// Look for the --passwordfile flag.
	if passphraseFile != "" {
		content, err := os.ReadFile(passphraseFile)
		if err != nil {
			utils.Fatalf("Failed to read password file '%s': %v",
				passphraseFile, err)
		}
		return strings.TrimRight(string(content), "\r\n")
	}

	// Otherwise prompt the user for the passphrase.
	return utils.GetPassPhrase("Enter passphrase for unlocking signer account: ", false)
}
