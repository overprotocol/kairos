// Copyright 2014 The go-ethereum Authors
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

package vm

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
	// GetHeaderByNumberFunc returns the header of the nth block in the chain
	// and is used to verify restoration proofs.
	GetHeaderByNumberFunc func(uint64) *types.Header
)

func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	var precompiles map[common.Address]PrecompiledContract
	switch {
	case evm.chainRules.IsCancun:
		precompiles = PrecompiledContractsCancun
	case evm.chainRules.IsAlpaca:
		precompiles = PrecompiledContractsAlpaca
	case evm.chainRules.IsBerlin:
		precompiles = PrecompiledContractsBerlin
	case evm.chainRules.IsIstanbul:
		precompiles = PrecompiledContractsIstanbul
	case evm.chainRules.IsByzantium:
		precompiles = PrecompiledContractsByzantium
	default:
		precompiles = PrecompiledContractsHomestead
	}
	p, ok := precompiles[addr]
	return p, ok
}

// BlockContext provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type BlockContext struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc
	// GetHeaderByNumber returns the header of the nth block in the chain
	GetHeaderByNumber GetHeaderByNumberFunc

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        uint64         // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
	BaseFee     *big.Int       // Provides information for BASEFEE (0 if vm runs with NoBaseFee flag and 0 gas price)
	BlobBaseFee *big.Int       // Provides information for BLOBBASEFEE (0 if vm runs with NoBaseFee flag and 0 blob gas price)
	Random      *common.Hash   // Provides information for PREVRANDAO
}

// TxContext provides the EVM with information about a transaction.
// All fields can change between transactions.
type TxContext struct {
	// Message information
	Origin     common.Address // Provides information for ORIGIN
	GasPrice   *big.Int       // Provides information for GASPRICE (and is used to zero the basefee if NoBaseFee is set)
	BlobHashes []common.Hash  // Provides information for BLOBHASH
	BlobFeeCap *big.Int       // Is used to zero the blobbasefee if NoBaseFee is set
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context BlockContext
	TxContext
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	Config Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreter *EVMInterpreter
	// abort is used to abort the EVM calling operations
	abort atomic.Bool
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64
}

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	// If basefee tracking is disabled (eth_call, eth_estimateGas, etc), and no
	// gas prices were specified, lower the basefee to 0 to avoid breaking EVM
	// invariants (basefee < feecap)
	if config.NoBaseFee {
		if txCtx.GasPrice.BitLen() == 0 {
			blockCtx.BaseFee = new(big.Int)
		}
		if txCtx.BlobFeeCap != nil && txCtx.BlobFeeCap.BitLen() == 0 {
			blockCtx.BlobBaseFee = new(big.Int)
		}
	}
	evm := &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time),
	}
	evm.interpreter = NewEVMInterpreter(evm)
	return evm
}

// Reset resets the EVM with a new transaction context.Reset
// This is not threadsafe and should only be done very cautiously.
func (evm *EVM) Reset(txCtx TxContext, statedb StateDB) {
	evm.TxContext = txCtx
	evm.StateDB = statedb
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	evm.abort.Store(true)
}

// Cancelled returns true if Cancel has been called
func (evm *EVM) Cancelled() bool {
	return evm.abort.Load()
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() *EVMInterpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)
	debug := evm.Config.Tracer != nil

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && evm.chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if debug {
				if evm.depth == 0 {
					evm.Config.Tracer.CaptureStart(evm, caller.Address(), addr, false, input, gas, value)
					evm.Config.Tracer.CaptureEnd(ret, 0, nil)
				} else {
					evm.Config.Tracer.CaptureEnter(CALL, caller.Address(), addr, input, gas, value)
					evm.Config.Tracer.CaptureExit(ret, 0, nil)
				}
			}
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}

	// Capture the tracer start/end events in debug mode
	if debug {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureStart(evm, caller.Address(), addr, false, input, gas, value)
			defer func(startGas uint64) { // Lazy evaluation of the parameters
				evm.Config.Tracer.CaptureEnd(ret, startGas-gas, err)
			}(gas)
		} else {
			// Handle tracer events for entering and exiting a call frame
			evm.Config.Tracer.CaptureEnter(CALL, caller.Address(), addr, input, gas, value)
			defer func(startGas uint64) {
				evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
			}(gas)
		}
	}

	if isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, caller, value, evm)
	} else {
		evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		code := evm.StateDB.GetCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // gas is unchanged
		} else {
			addrCopy := addr
			// If the account has no code, we can abort here
			// The depth-check is already done, and precompiles handled above
			contract := NewContract(caller, AccountRef(addrCopy), value, gas)
			contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), code)
			ret, err = evm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	evm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// Note although it's noop to transfer X ether to caller itself. But
	// if caller doesn't have enough balance, it would be an error to allow
	// over-charging itself. So the check here is necessary.
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	var snapshot = evm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		evm.Config.Tracer.CaptureEnter(CALLCODE, caller.Address(), addr, input, gas, value)
		defer func(startGas uint64) {
			evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, caller, value, evm)
	} else {
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, AccountRef(caller.Address()), value, gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	var snapshot = evm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		// NOTE: caller must, at all times be a contract. It should never happen
		// that caller is something other than a Contract.
		parent := caller.(*Contract)
		// DELEGATECALL inherits value from parent call
		evm.Config.Tracer.CaptureEnter(DELEGATECALL, caller.Address(), addr, input, gas, parent.value)
		defer func(startGas uint64) {
			evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, caller, big.NewInt(0), evm)
	} else {
		addrCopy := addr
		// Initialise a new contract and make initialise the delegate values
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// We take a snapshot here. This is a bit counter-intuitive, and could probably be skipped.
	// However, even a staticcall is considered a 'touch'. On mainnet, static calls were introduced
	// after all empty accounts were deleted, so this is not required. However, if we omit this,
	// then certain tests start failing; stRevertTest/RevertPrecompiledTouchExactOOG.json.
	// We could change this, but for now it's left for legacy reasons
	var snapshot = evm.StateDB.Snapshot()

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	evm.StateDB.AddBalance(addr, big0)

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Tracer != nil {
		evm.Config.Tracer.CaptureEnter(STATICCALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas, caller, big.NewInt(0), evm)
	} else {
		// At this point, we use a copy of address. If we don't, the go compiler will
		// leak the 'contract' to the outer scope, and make allocation for 'contract'
		// even if the actual execution ends on RunPrecompiled above.
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, AccountRef(addrCopy), new(big.Int), gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		// When an error was returned by the EVM or when setting the creation code
		// above we revert to the snapshot and consume any gas remaining. Additionally
		// when we're in Homestead this also counts for code storage gas errors.
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

type uiHash struct {
	input  []byte
	uiHash common.Hash
}

func (c *uiHash) Unpack() error {
	// unpack input data
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return err
	}

	arguments := abi.Arguments{
		{Type: bytes32Ty}, // ui bytecode hash
	}

	result, err := arguments.Unpack(c.input)
	if err != nil {
		return err
	}

	c.uiHash = result[0].([32]uint8)

	return nil
}

type codeAndUiHash struct {
	input       []byte
	salt        common.Hash
	codeAndHash *codeAndHash
	uiHash      common.Hash
}

func (c *codeAndUiHash) Unpack() error {
	// unpack input data
	bytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return err
	}
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return err
	}

	arguments := abi.Arguments{
		{Type: bytesTy},   // contract deployment bytecode
		{Type: bytes32Ty}, // ui bytecode hash
	}

	result, err := arguments.Unpack(c.input)
	if err != nil {
		return err
	}

	c.codeAndHash = &codeAndHash{code: result[0].([]byte)}
	c.uiHash = result[1].([32]uint8)

	return nil
}

func (c *codeAndUiHash) UnpackWithSalt() error {
	// unpack input data
	bytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return err
	}
	bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return err
	}

	arguments := abi.Arguments{
		{Type: bytes32Ty}, // salt for create2
		{Type: bytesTy},   // contract deployment bytecode
		{Type: bytes32Ty}, // ui bytecode hash
	}

	result, err := arguments.Unpack(c.input)
	if err != nil {
		return err
	}

	c.salt = result[0].([32]uint8)
	c.codeAndHash = &codeAndHash{code: result[1].([]byte)}
	c.uiHash = result[2].([32]uint8)

	return nil
}

// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address, typ OpCode) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	// We add this to the access list _before_ taking a snapshot. Even if the creation fails,
	// the access-list change should not be rolled back
	if evm.chainRules.IsBerlin {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	if typ == CREATE2 && evm.StateDB.GetEpochCoverage(address) != 0 {
		return nil, common.Address{}, 0, ErrCreate2NotAvailable
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.Config.Tracer != nil {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureStart(evm, caller.Address(), address, true, codeAndHash.code, gas, value)
		} else {
			evm.Config.Tracer.CaptureEnter(typ, caller.Address(), address, codeAndHash.code, gas, value)
		}
	}

	ret, err := evm.interpreter.Run(contract, nil, false)

	// Check whether the max code size has been exceeded, assign err if the case.
	if err == nil && evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		err = ErrInvalidCode
	}

	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	if evm.Config.Tracer != nil {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureEnd(ret, gas-contract.Gas, err)
		} else {
			evm.Config.Tracer.CaptureExit(ret, gas-contract.Gas, err)
		}
	}
	return ret, address, contract.Gas, err
}

// createWithUi creates a new contract and sets the ui hash
func (evm *EVM) createWithUi(caller ContractRef, codeAndUiHash *codeAndUiHash, gas uint64, value *big.Int, address common.Address, typ OpCode) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	// We add this to the access list _before_ taking a snapshot. Even if the creation fails,
	// the access-list change should not be rolled back
	if evm.chainRules.IsBerlin {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	if typ == CREATE2 && evm.StateDB.GetEpochCoverage(address) != 0 {
		return nil, common.Address{}, 0, ErrCreate2NotAvailable
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndUiHash.codeAndHash)

	if evm.Config.Tracer != nil {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureStart(evm, caller.Address(), address, true, codeAndUiHash.input, gas, value)
		} else {
			evm.Config.Tracer.CaptureEnter(typ, caller.Address(), address, codeAndUiHash.input, gas, value)
		}
	}

	ret, err := evm.interpreter.Run(contract, nil, false)

	// Check whether the max code size has been exceeded, assign err if the case.
	if err == nil && evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		err = ErrInvalidCode
	}

	// If the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	if evm.StateDB.Exist(address) {
		evm.StateDB.SetUiHash(address, codeAndUiHash.uiHash)
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	if evm.Config.Tracer != nil {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureEnd(ret, gas-contract.Gas, err)
		} else {
			evm.Config.Tracer.CaptureExit(ret, gas-contract.Gas, err)
		}
	}
	return ret, address, contract.Gas, err
}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetEpochCoverage(caller.Address()), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr, CREATE2)
}

func (evm *EVM) CreateWithUiHash(caller ContractRef, input []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndUiHash := codeAndUiHash{input: input}
	if err := codeAndUiHash.Unpack(); err != nil {
		return nil, common.Address{}, gas, err
	}

	// Update nonce if the caller is a contract
	if contractHash := evm.StateDB.GetCodeHash(caller.Address()); contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash {
		nonce := evm.StateDB.GetNonce(caller.Address())
		if nonce+1 < nonce {
			return nil, common.Address{}, gas, ErrNonceUintOverflow
		}
		evm.StateDB.SetNonce(caller.Address(), nonce+1)
	}

	// Nonce of caller can not be zero
	// In case of EOA, nonce is incremented by 1 before calling CreateWithUiHash
	// In case of CA, nonce is incremented by 1 inside of CreateWithUiHash
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetEpochCoverage(caller.Address()), evm.StateDB.GetNonce(caller.Address())-1)
	return evm.createWithUi(caller, &codeAndUiHash, gas, value, contractAddr, CREATE)
}

// Create2WithUiHash creates a new contract and sets the ui hash.
func (evm *EVM) Create2WithUiHash(caller ContractRef, input []byte, gas uint64, endowment *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndUiHash := codeAndUiHash{input: input}
	if err := codeAndUiHash.UnpackWithSalt(); err != nil {
		return nil, common.Address{}, gas, err
	}

	// Update nonce if the caller is a contract
	if contractHash := evm.StateDB.GetCodeHash(caller.Address()); contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash {
		nonce := evm.StateDB.GetNonce(caller.Address())
		if nonce+1 < nonce {
			return nil, common.Address{}, gas, ErrNonceUintOverflow
		}
		evm.StateDB.SetNonce(caller.Address(), nonce+1)
	}

	contractAddr = crypto.CreateAddress2(caller.Address(), codeAndUiHash.salt, codeAndUiHash.codeAndHash.Hash().Bytes())
	return evm.createWithUi(caller, &codeAndUiHash, gas, endowment, contractAddr, CREATE)
}

// ChangeUiHash changes the ui hash of the account
func (evm *EVM) ChangeUiHash(caller ContractRef, input []byte) (err error) {
	uiHash := uiHash{input: input}
	if err := uiHash.Unpack(); err != nil {
		return err
	}

	if evm.depth > int(params.CallCreateDepth) {
		return ErrDepth
	}

	evm.StateDB.SetUiHash(caller.Address(), uiHash.uiHash)

	return nil
}

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// Restore restores the account state from the given restore data.
// For the restoration to happen the restoration proof has to be valid
// and the sender of the restore data (different from the sender of the transaction)
// has to have enough balance to send the restoration fee.
//
// Note that restoration of a contract account is currently not supported.
func (evm *EVM) Restore(caller ContractRef, input []byte, restoreData *types.RestoreData, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if restoreData.TargetEpoch >= restoreData.SourceEpoch {
		return nil, 0, ErrInvalidTargetEpoch
	}

	// Retrieve the sender from the restore data using restore data signer
	restoreDataSigner := types.LatestRestoreDataSigner(evm.chainConfig)
	sender, err := restoreDataSigner.Sender(restoreData)
	if err != nil {
		return nil, 0, err
	}
	// Retrieve and get the current state of the target account
	target := restoreData.Target
	// Check sender can pay the restoration fee first.
	if sender != target {
		if !evm.Context.CanTransfer(evm.StateDB, sender, restoreData.Fee) {
			return nil, gas, ErrInsufficientBalance
		}
	}
	epochCoverage := evm.StateDB.GetEpochCoverage(target)
	nonce := evm.StateDB.GetNonce(target)
	// Disable restoration if the target account is contract
	if codeHash := evm.StateDB.GetCodeHash(target); codeHash != types.EmptyCodeHash && codeHash != (common.Hash{}) {
		return nil, 0, ErrContractRestoration
	}

	if restoreData.SourceEpoch != epochCoverage {
		return nil, gas, ErrInvalidSourceEpoch
	}

	memoryCost, err := memoryGasCost(NewMemory(), uint64(len(input)))
	if err != nil {
		return nil, gas, err
	}
	restoreWordCost := params.RestorePerWordGas * toWordSize(uint64(len(input)))
	if restoreDataGas := restoreWordCost + memoryCost; restoreDataGas <= gas {
		gas -= restoreDataGas
	} else {
		return nil, gas, ErrRestoreDataOutOfGas
	}

	// Retrieve and verify the restoration proof
	var rawProofs [][][]byte
	err = rlp.DecodeBytes(input, &rawProofs)
	if err != nil {
		return nil, 0, err
	}

	if restoreDataGas := params.RestorePerEpochGas * uint64(len(rawProofs)); restoreDataGas <= gas {
		gas -= restoreDataGas
	} else {
		return nil, gas, ErrRestoreDataOutOfGas
	}

	epochCoverage, nonce, restoredBalance, err := evm.verifyRestorationProof(target, restoreData.TargetEpoch, rawProofs, epochCoverage, nonce)
	if err != nil {
		return nil, 0, err
	}

	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.SetEpochCoverage(target, epochCoverage)
	evm.StateDB.SetNonce(target, nonce)
	if restoredBalance.Sign() != 0 {
		evm.StateDB.AddBalance(target, restoredBalance)
	}
	// The sender of the restore data has to have enough balance to send the restoration fee
	if restoreData.FeeRecipient != nil && restoreData.Fee.Sign() != 0 {
		// the case where the sender is not the target account already checked above
		if sender == target && !evm.Context.CanTransfer(evm.StateDB, sender, restoreData.Fee) {
			err = ErrInsufficientBalance
		} else {
			evm.Context.Transfer(evm.StateDB, sender, *restoreData.FeeRecipient, restoreData.Fee)
		}
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
	}
	return nil, gas, err
}

// verifyRestorationProof verifies the restoration proof and returns the epoch coverage, nonce and balance.
// Note that this function is currently not supported for contract accounts since restoration is not supported.
func (evm *EVM) verifyRestorationProof(target common.Address, targetEpoch uint32, rawProofs [][][]byte, epochCoverage uint32, nonce uint32) (uint32, uint32, *big.Int, error) {
	restoredBalance := big.NewInt(0)
	targetKey := crypto.Keccak256Hash(target.Bytes()).Bytes()
	for _, rawProof := range rawProofs {
		proofDB := NewProofDB(rawProof)

		lastCkptBn, exist := evm.chainConfig.CalcLastCheckpointBlockNumber(epochCoverage)
		if !exist {
			return 0, 0, nil, ErrZeroEpochCoverage
		}

		header := evm.Context.GetHeaderByNumber(lastCkptBn)
		if header == nil {
			return 0, 0, nil, ErrHeaderIsNil
		}
		leafNode, err := trie.VerifyProofUnsafe(header.Root, targetKey, proofDB)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("merkle proof verification failed: %v", err)
		}
		if leafNode == nil {
			// The account does not exist in this epoch
			epochCoverage = epochCoverage - 1
		} else {
			var account types.StateAccount
			err = rlp.DecodeBytes(leafNode, &account)
			if err != nil {
				return 0, 0, nil, fmt.Errorf("failed to decode account: %v", err)
			}
			// Disable restoration if the target account is contract
			// There is no need to check if codeHash != (common.Hash{}). The reason is that if codeHash is
			// common.Hash, it represents an empty account. Since the Merkle proof for an empty account will
			// be a void proof, common.Hash will not appear in the proof.
			if common.BytesToHash(account.CodeHash) != types.EmptyCodeHash {
				return 0, 0, nil, ErrContractRestoration
			}
			epochCoverage = account.EpochCoverage
			if nonce+account.Nonce < nonce {
				return 0, 0, nil, ErrNonceUintOverflow
			}
			nonce += account.Nonce
			if account.Balance.Sign() != 0 {
				restoredBalance = new(big.Int).Add(restoredBalance, account.Balance)
			}
		}
	}
	if epochCoverage > targetEpoch {
		return 0, 0, nil, ErrEpochProofMismatch
	}
	return epochCoverage, nonce, restoredBalance, nil
}

type ProofDB struct {
	nodes map[string][]byte
}

func NewProofDB(rawData [][]byte) *ProofDB {
	db := ProofDB{
		nodes: make(map[string][]byte),
	}
	for _, node := range rawData {
		db.Put(crypto.Keccak256(node), node)
	}
	return &db
}

func (db *ProofDB) Put(key []byte, value []byte) {
	keystr := string(key)

	db.nodes[keystr] = common.CopyBytes(value)
}

func (db *ProofDB) Get(key []byte) ([]byte, error) {
	if entry, ok := db.nodes[string(key)]; ok {
		return entry, nil
	}
	return nil, errors.New("not found")
}

func (db *ProofDB) Has(key []byte) (bool, error) {
	_, err := db.Get(key)
	return err == nil, nil
}
