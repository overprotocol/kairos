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

package core

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

/*
pragma solidity 0.8.13;

contract TestUiCode {
		address createWithUiAddress = 0x00000000000000000000000000000000000000F5;
		address create2WithUiAddress = 0x00000000000000000000000000000000000000F4;
		address changUiAddress = 0x00000000000000000000000000000000000000f3;
		address public createdAddress;
		constructor() payable {}
		function CreateWithUi(bytes calldata input) public payable {
				(bool success, bytes memory returnData) = createWithUiAddress.call{
						value: msg.value
				}(input);
				require(success, "CreateWithUi: call failed");
				(, address newAddr) = abi.decode(returnData, (bytes, address));
				createdAddress = newAddr;
		}
		function Create2WithUi(bytes calldata input) public payable {
				(bool success, bytes memory returnData) = create2WithUiAddress.call{
						value: msg.value
				}(input);
				require(success, "Create2WithUi: call failed");
				(, address newAddr) = abi.decode(returnData, (bytes, address));
				createdAddress = newAddr;
		}
		function ChangeUi(bytes calldata input) public payable {
				(bool success, ) = changUiAddress.call{value: msg.value}(input);
				require(success, "ChangeUi: call failed");
		}
}
*/

var (
	uiContractAbi, _           = abi.JSON(strings.NewReader("[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"input\",\"type\":\"bytes\"}],\"name\":\"ChangeUi\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"input\",\"type\":\"bytes\"}],\"name\":\"Create2WithUi\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"input\",\"type\":\"bytes\"}],\"name\":\"CreateWithUi\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"createdAddress\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"))
	uiContractByteCode         = common.FromHex("0x6080604052600080546001600160a01b031990811660f51790915560018054821660f41790556002805490911660f3179055610502806100406000396000f3fe60806040526004361061003f5760003560e01c8063270dc7f5146100445780635d54a1cd14610080578063cd44582f14610095578063dbedce35146100a8575b600080fd5b34801561005057600080fd5b50600354610064906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b61009361008e366004610335565b6100bb565b005b6100936100a3366004610335565b6101c5565b6100936100b6366004610335565b61027f565b60015460405160009182916001600160a01b039091169034906100e190879087906103a7565b60006040518083038185875af1925050503d806000811461011e576040519150601f19603f3d011682016040523d82523d6000602084013e610123565b606091505b50915091508161017a5760405162461bcd60e51b815260206004820152601a60248201527f437265617465325769746855693a2063616c6c206661696c656400000000000060448201526064015b60405180910390fd5b60008180602001905181019061019091906103e9565b6003805473ffffffffffffffffffffffffffffffffffffffff19166001600160a01b0392909216919091179055505050505050565b6002546040516000916001600160a01b03169034906101e790869086906103a7565b60006040518083038185875af1925050503d8060008114610224576040519150601f19603f3d011682016040523d82523d6000602084013e610229565b606091505b505090508061027a5760405162461bcd60e51b815260206004820152601560248201527f4368616e676555693a2063616c6c206661696c656400000000000000000000006044820152606401610171565b505050565b6000805460405182916001600160a01b03169034906102a190879087906103a7565b60006040518083038185875af1925050503d80600081146102de576040519150601f19603f3d011682016040523d82523d6000602084013e6102e3565b606091505b50915091508161017a5760405162461bcd60e51b815260206004820152601960248201527f4372656174655769746855693a2063616c6c206661696c6564000000000000006044820152606401610171565b6000806020838503121561034857600080fd5b823567ffffffffffffffff8082111561036057600080fd5b818501915085601f83011261037457600080fd5b81358181111561038357600080fd5b86602082850101111561039557600080fd5b60209290920196919550909350505050565b8183823760009101908152919050565b634e487b7160e01b600052604160045260246000fd5b80516001600160a01b03811681146103e457600080fd5b919050565b600080604083850312156103fc57600080fd5b825167ffffffffffffffff8082111561041457600080fd5b818501915085601f83011261042857600080fd5b81518181111561043a5761043a6103b7565b604051601f8201601f19908116603f01168101908382118183101715610462576104626103b7565b8160405282815260209350888484870101111561047e57600080fd5b600091505b828210156104a05784820184015181830185015290830190610483565b828211156104b15760008484830101525b95506104c19150508582016103cd565b92505050925092905056fea264697066735822122074e0aa2da2241f18353ab6dba8032d071bc643f18658b8111936b4a8b00bd23d64736f6c634300080d0033")
	deployedUiContractByteCode = common.FromHex("0x60806040526004361061003f5760003560e01c8063270dc7f5146100445780635d54a1cd14610080578063cd44582f14610095578063dbedce35146100a8575b600080fd5b34801561005057600080fd5b50600354610064906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b61009361008e366004610335565b6100bb565b005b6100936100a3366004610335565b6101c5565b6100936100b6366004610335565b61027f565b60015460405160009182916001600160a01b039091169034906100e190879087906103a7565b60006040518083038185875af1925050503d806000811461011e576040519150601f19603f3d011682016040523d82523d6000602084013e610123565b606091505b50915091508161017a5760405162461bcd60e51b815260206004820152601a60248201527f437265617465325769746855693a2063616c6c206661696c656400000000000060448201526064015b60405180910390fd5b60008180602001905181019061019091906103e9565b6003805473ffffffffffffffffffffffffffffffffffffffff19166001600160a01b0392909216919091179055505050505050565b6002546040516000916001600160a01b03169034906101e790869086906103a7565b60006040518083038185875af1925050503d8060008114610224576040519150601f19603f3d011682016040523d82523d6000602084013e610229565b606091505b505090508061027a5760405162461bcd60e51b815260206004820152601560248201527f4368616e676555693a2063616c6c206661696c656400000000000000000000006044820152606401610171565b505050565b6000805460405182916001600160a01b03169034906102a190879087906103a7565b60006040518083038185875af1925050503d80600081146102de576040519150601f19603f3d011682016040523d82523d6000602084013e6102e3565b606091505b50915091508161017a5760405162461bcd60e51b815260206004820152601960248201527f4372656174655769746855693a2063616c6c206661696c6564000000000000006044820152606401610171565b6000806020838503121561034857600080fd5b823567ffffffffffffffff8082111561036057600080fd5b818501915085601f83011261037457600080fd5b81358181111561038357600080fd5b86602082850101111561039557600080fd5b60209290920196919550909350505050565b8183823760009101908152919050565b634e487b7160e01b600052604160045260246000fd5b80516001600160a01b03811681146103e457600080fd5b919050565b600080604083850312156103fc57600080fd5b825167ffffffffffffffff8082111561041457600080fd5b818501915085601f83011261042857600080fd5b81518181111561043a5761043a6103b7565b604051601f8201601f19908116603f01168101908382118183101715610462576104626103b7565b8160405282815260209350888484870101111561047e57600080fd5b600091505b828210156104a05784820184015181830185015290830190610483565b828211156104b15760008484830101525b95506104c19150508582016103cd565b92505050925092905056fea264697066735822122074e0aa2da2241f18353ab6dba8032d071bc643f18658b8111936b4a8b00bd23d64736f6c634300080d0033")
	uiHash                     = crypto.Keccak256Hash([]byte("uiHash"))
	salt                       = common.BytesToHash([]byte("salt"))
)

func TestEOACreateWithUI(t *testing.T) {
	// given
	bc := createBlockChain(true, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	nonceBefore := state.GetNonce(addr1)

	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := packCreateWithUiParams(uiContractByteCode, uiHash)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), common.CreateWithUiHashAddress, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
		contractAddr = crypto.CreateAddress(addr1, tx.Nonce())
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err = bc.State()
	if err != nil {
		t.Fatal(err)
	}

	if code := state.GetCode(contractAddr); !bytes.Equal(code, deployedUiContractByteCode) {
		t.Errorf("code mismatch: %v, %v\n", common.Bytes2Hex(deployedUiContractByteCode[:]), common.Bytes2Hex(code[:]))
	}
	if balance := state.GetBalance(contractAddr); balance.Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("balance mismatch: %v, %v\n", 10000, balance.String())
	}
	if hash := state.GetUiHash(contractAddr); hash != uiHash {
		t.Errorf("uiHash mismatch: %v, %v\n", uiHash, hash)
	}
	if nonceAfter := state.GetNonce(addr1); nonceAfter != nonceBefore+1 {
		t.Errorf("nonce mismatch: %v, %v\n", nonceBefore+1, nonceAfter)
	}
}

func TestEOACreate2WithUI(t *testing.T) {
	// given
	bc := createBlockChain(true, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	nonceBefore := state.GetNonce(addr1)

	blocks, receipts := blockGenerator.createBlockListWithReceipt(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := packCreate2WithUiParams(uiContractByteCode, uiHash, salt)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), common.Create2WithUiHashAddress, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
	})

	if i, err := bc.InsertChain(blocks); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	if receipts[0][0].Status != types.ReceiptStatusFailed {
		t.Errorf("EOA can not create contract with create2")
	}
	state, err = bc.State()
	if err != nil {
		t.Fatal(err)
	}
	if nonceAfter := state.GetNonce(addr1); nonceAfter != nonceBefore+1 {
		t.Errorf("nonce mismatch: %v, %v\n", nonceBefore+1, nonceAfter)
	}
}

func TestEOAChangeUi(t *testing.T) {
	bc := createBlockChain(true, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}
	nonceBefore := state.GetNonce(addr1)

	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := packChangeUiParams(uiHash)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), common.ChangeUiHashAddress, nil, 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err = bc.State()
	if err != nil {
		t.Fatal(err)
	}

	if hash := state.GetUiHash(addr1); hash != uiHash {
		t.Errorf("uiHash mismatch: %v, %v\n", uiHash, hash)
	}
	if nonceAfter := state.GetNonce(addr1); nonceAfter != nonceBefore+1 {
		t.Errorf("nonce mismatch: %v, %v\n", nonceBefore+1, nonceAfter)
	}
}

func TestCACreateWithUI(t *testing.T) {
	// given
	bc := createBlockChain(true, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := packCreateWithUiParams(uiContractByteCode, uiHash)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), common.CreateWithUiHashAddress, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
		contractAddr = crypto.CreateAddress(addr1, tx.Nonce())
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}

	nonceBefore := state.GetNonce(contractAddr)

	var contractAddr2 common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := createCreateWithUiInput(uiContractByteCode, uiHash)
		if err != nil {
			t.Fatal(err)
		}
		txNonce := gen.statedb.GetTxNonce(contractAddr)
		tx := types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
		contractAddr2 = crypto.CreateAddress(contractAddr, txNonce)
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err = bc.State()
	if err != nil {
		t.Fatal(err)
	}

	if code := state.GetCode(contractAddr2); !bytes.Equal(code, deployedUiContractByteCode) {
		t.Errorf("code mismatch: %v, %v\n", deployedUiContractByteCode, code)
	}
	if balance := state.GetBalance(contractAddr2); balance.Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("balance mismatch: %v, %v\n", 10000, balance.String())
	}
	if hash := state.GetUiHash(contractAddr2); hash != uiHash {
		t.Errorf("uiHash mismatch: %v, %v\n", uiHash, hash)
	}
	if nonceAfter := state.GetNonce(contractAddr); nonceAfter != nonceBefore+1 {
		t.Errorf("nonce mismatch: %v, %v\n", nonceBefore+1, nonceAfter)
	}
}

func TestCACreate2WithUI(t *testing.T) {
	// given
	bc := createBlockChain(true, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := packCreateWithUiParams(uiContractByteCode, uiHash)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), common.CreateWithUiHashAddress, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
		contractAddr = crypto.CreateAddress(addr1, tx.Nonce())
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}

	nonceBefore := state.GetNonce(contractAddr)

	var contractAddr2 common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := createCreate2WithUiInput(uiContractByteCode, uiHash, salt)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), contractAddr, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
		contractAddr2 = crypto.CreateAddress2(contractAddr, salt, crypto.Keccak256(uiContractByteCode))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err = bc.State()
	if err != nil {
		t.Fatal(err)
	}

	if code := state.GetCode(contractAddr2); !bytes.Equal(code, deployedUiContractByteCode) {
		t.Errorf("code mismatch: %v, %v\n", deployedUiContractByteCode, code)
	}
	if balance := state.GetBalance(contractAddr2); balance.Cmp(big.NewInt(10000)) != 0 {
		t.Errorf("balance mismatch: %v, %v\n", 10000, balance.String())
	}
	if hash := state.GetUiHash(contractAddr2); hash != uiHash {
		t.Errorf("uiHash mismatch: %v, %v\n", uiHash, hash)
	}
	if nonceAfter := state.GetNonce(contractAddr); nonceAfter != nonceBefore+1 {
		t.Errorf("nonce mismatch: %v, %v\n", nonceBefore+1, nonceAfter)
	}
}

func TestCAChangeUi(t *testing.T) {
	// given
	bc := createBlockChain(true, false, rawdb.HashScheme)
	defer bc.Stop()
	blockGenerator := createBlockGenerator(false)

	var contractAddr common.Address
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := packCreateWithUiParams(uiContractByteCode, uiHash)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), common.CreateWithUiHashAddress, big.NewInt(10000), 3000000, nil, input)
		gen.AddTx(signTx(tx, key1))
		contractAddr = crypto.CreateAddress(addr1, tx.Nonce())
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	uiHash2 := crypto.Keccak256Hash([]byte("uiHash2"))
	if i, err := bc.InsertChain(blockGenerator.createBlockList(1, func(i int, gen *BlockGen) {
		// deploy contract with uihash
		input, err := createChangeUiInput(uiHash2)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.NewTransaction(gen.TxNonce(addr1), contractAddr, nil, 300000, nil, input)
		gen.AddTx(signTx(tx, key1))
	})); err != nil {
		t.Errorf("insert error (block index %d): %v\n", i, err)
	}

	state, err := bc.State()
	if err != nil {
		t.Fatal(err)
	}

	if hash := state.GetUiHash(contractAddr); hash != uiHash2 {
		t.Errorf("uiHash mismatch: %v, %v\n", uiHash2, hash)
	}
}

func packCreateWithUiParams(contractCode []byte, uiHash common.Hash) ([]byte, error) {
	bytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}

	arguments := abi.Arguments{
		{Type: bytesTy},   // contract deployment bytecode
		{Type: bytes32Ty}, // ui hash
	}

	packed, err := arguments.Pack(contractCode, uiHash)
	if err != nil {
		return nil, err
	}

	return packed, nil
}

func packCreate2WithUiParams(contractCode []byte, uiHash common.Hash, salt common.Hash) ([]byte, error) {
	bytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}

	arguments := abi.Arguments{
		{Type: bytes32Ty}, // salt for create2
		{Type: bytesTy},   // contract deployment bytecode
		{Type: bytes32Ty}, // ui hash
	}

	packed, err := arguments.Pack(salt, contractCode, uiHash)
	if err != nil {
		return nil, err
	}

	return packed, nil
}

func packChangeUiParams(uiHash common.Hash) ([]byte, error) {
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return nil, err
	}

	arguments := abi.Arguments{
		{Type: bytes32Ty}, // ui hash
	}

	packed, err := arguments.Pack(uiHash)
	if err != nil {
		return nil, err
	}

	return packed, nil
}

func createCreateWithUiInput(contractCode []byte, uiHash common.Hash) ([]byte, error) {
	packed, err := packCreateWithUiParams(contractCode, uiHash)
	if err != nil {
		return nil, err
	}

	input, err := uiContractAbi.Pack("CreateWithUi", packed)
	if err != nil {
		return nil, err
	}

	return input, nil
}

func createCreate2WithUiInput(contractCode []byte, uiHash common.Hash, salt common.Hash) ([]byte, error) {
	packed, err := packCreate2WithUiParams(contractCode, uiHash, salt)
	if err != nil {
		return nil, err
	}

	input, err := uiContractAbi.Pack("Create2WithUi", packed)
	if err != nil {
		return nil, err
	}

	return input, nil
}

func createChangeUiInput(uiHash common.Hash) ([]byte, error) {
	packed, err := packChangeUiParams(uiHash)
	if err != nil {
		return nil, err
	}

	input, err := uiContractAbi.Pack("ChangeUi", packed)
	if err != nil {
		return nil, err
	}

	return input, nil
}

func createCreatedAddressInput() ([]byte, error) {
	input, err := uiContractAbi.Pack("createdAddress")
	if err != nil {
		return nil, err
	}

	return input, nil
}
