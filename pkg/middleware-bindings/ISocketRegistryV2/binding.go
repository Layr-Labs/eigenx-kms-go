// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package ISocketRegistryV2

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// ISocketRegistryV2MetaData contains all meta data concerning the ISocketRegistryV2 contract.
var ISocketRegistryV2MetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"getOperatorSocket\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"updateSocket\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"socket\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"OperatorSocketSet\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"socket\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false}]",
}

// ISocketRegistryV2ABI is the input ABI used to generate the binding from.
// Deprecated: Use ISocketRegistryV2MetaData.ABI instead.
var ISocketRegistryV2ABI = ISocketRegistryV2MetaData.ABI

// ISocketRegistryV2 is an auto generated Go binding around an Ethereum contract.
type ISocketRegistryV2 struct {
	ISocketRegistryV2Caller     // Read-only binding to the contract
	ISocketRegistryV2Transactor // Write-only binding to the contract
	ISocketRegistryV2Filterer   // Log filterer for contract events
}

// ISocketRegistryV2Caller is an auto generated read-only Go binding around an Ethereum contract.
type ISocketRegistryV2Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISocketRegistryV2Transactor is an auto generated write-only Go binding around an Ethereum contract.
type ISocketRegistryV2Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISocketRegistryV2Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ISocketRegistryV2Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISocketRegistryV2Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ISocketRegistryV2Session struct {
	Contract     *ISocketRegistryV2 // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// ISocketRegistryV2CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ISocketRegistryV2CallerSession struct {
	Contract *ISocketRegistryV2Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// ISocketRegistryV2TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ISocketRegistryV2TransactorSession struct {
	Contract     *ISocketRegistryV2Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// ISocketRegistryV2Raw is an auto generated low-level Go binding around an Ethereum contract.
type ISocketRegistryV2Raw struct {
	Contract *ISocketRegistryV2 // Generic contract binding to access the raw methods on
}

// ISocketRegistryV2CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ISocketRegistryV2CallerRaw struct {
	Contract *ISocketRegistryV2Caller // Generic read-only contract binding to access the raw methods on
}

// ISocketRegistryV2TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ISocketRegistryV2TransactorRaw struct {
	Contract *ISocketRegistryV2Transactor // Generic write-only contract binding to access the raw methods on
}

// NewISocketRegistryV2 creates a new instance of ISocketRegistryV2, bound to a specific deployed contract.
func NewISocketRegistryV2(address common.Address, backend bind.ContractBackend) (*ISocketRegistryV2, error) {
	contract, err := bindISocketRegistryV2(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ISocketRegistryV2{ISocketRegistryV2Caller: ISocketRegistryV2Caller{contract: contract}, ISocketRegistryV2Transactor: ISocketRegistryV2Transactor{contract: contract}, ISocketRegistryV2Filterer: ISocketRegistryV2Filterer{contract: contract}}, nil
}

// NewISocketRegistryV2Caller creates a new read-only instance of ISocketRegistryV2, bound to a specific deployed contract.
func NewISocketRegistryV2Caller(address common.Address, caller bind.ContractCaller) (*ISocketRegistryV2Caller, error) {
	contract, err := bindISocketRegistryV2(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ISocketRegistryV2Caller{contract: contract}, nil
}

// NewISocketRegistryV2Transactor creates a new write-only instance of ISocketRegistryV2, bound to a specific deployed contract.
func NewISocketRegistryV2Transactor(address common.Address, transactor bind.ContractTransactor) (*ISocketRegistryV2Transactor, error) {
	contract, err := bindISocketRegistryV2(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ISocketRegistryV2Transactor{contract: contract}, nil
}

// NewISocketRegistryV2Filterer creates a new log filterer instance of ISocketRegistryV2, bound to a specific deployed contract.
func NewISocketRegistryV2Filterer(address common.Address, filterer bind.ContractFilterer) (*ISocketRegistryV2Filterer, error) {
	contract, err := bindISocketRegistryV2(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ISocketRegistryV2Filterer{contract: contract}, nil
}

// bindISocketRegistryV2 binds a generic wrapper to an already deployed contract.
func bindISocketRegistryV2(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := ISocketRegistryV2MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ISocketRegistryV2 *ISocketRegistryV2Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ISocketRegistryV2.Contract.ISocketRegistryV2Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ISocketRegistryV2 *ISocketRegistryV2Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISocketRegistryV2.Contract.ISocketRegistryV2Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ISocketRegistryV2 *ISocketRegistryV2Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ISocketRegistryV2.Contract.ISocketRegistryV2Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ISocketRegistryV2 *ISocketRegistryV2CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ISocketRegistryV2.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ISocketRegistryV2 *ISocketRegistryV2TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISocketRegistryV2.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ISocketRegistryV2 *ISocketRegistryV2TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ISocketRegistryV2.Contract.contract.Transact(opts, method, params...)
}

// GetOperatorSocket is a free data retrieval call binding the contract method 0x8481931d.
//
// Solidity: function getOperatorSocket(address operator) view returns(string)
func (_ISocketRegistryV2 *ISocketRegistryV2Caller) GetOperatorSocket(opts *bind.CallOpts, operator common.Address) (string, error) {
	var out []interface{}
	err := _ISocketRegistryV2.contract.Call(opts, &out, "getOperatorSocket", operator)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// GetOperatorSocket is a free data retrieval call binding the contract method 0x8481931d.
//
// Solidity: function getOperatorSocket(address operator) view returns(string)
func (_ISocketRegistryV2 *ISocketRegistryV2Session) GetOperatorSocket(operator common.Address) (string, error) {
	return _ISocketRegistryV2.Contract.GetOperatorSocket(&_ISocketRegistryV2.CallOpts, operator)
}

// GetOperatorSocket is a free data retrieval call binding the contract method 0x8481931d.
//
// Solidity: function getOperatorSocket(address operator) view returns(string)
func (_ISocketRegistryV2 *ISocketRegistryV2CallerSession) GetOperatorSocket(operator common.Address) (string, error) {
	return _ISocketRegistryV2.Contract.GetOperatorSocket(&_ISocketRegistryV2.CallOpts, operator)
}

// UpdateSocket is a paid mutator transaction binding the contract method 0x6591666a.
//
// Solidity: function updateSocket(address operator, string socket) returns()
func (_ISocketRegistryV2 *ISocketRegistryV2Transactor) UpdateSocket(opts *bind.TransactOpts, operator common.Address, socket string) (*types.Transaction, error) {
	return _ISocketRegistryV2.contract.Transact(opts, "updateSocket", operator, socket)
}

// UpdateSocket is a paid mutator transaction binding the contract method 0x6591666a.
//
// Solidity: function updateSocket(address operator, string socket) returns()
func (_ISocketRegistryV2 *ISocketRegistryV2Session) UpdateSocket(operator common.Address, socket string) (*types.Transaction, error) {
	return _ISocketRegistryV2.Contract.UpdateSocket(&_ISocketRegistryV2.TransactOpts, operator, socket)
}

// UpdateSocket is a paid mutator transaction binding the contract method 0x6591666a.
//
// Solidity: function updateSocket(address operator, string socket) returns()
func (_ISocketRegistryV2 *ISocketRegistryV2TransactorSession) UpdateSocket(operator common.Address, socket string) (*types.Transaction, error) {
	return _ISocketRegistryV2.Contract.UpdateSocket(&_ISocketRegistryV2.TransactOpts, operator, socket)
}

// ISocketRegistryV2OperatorSocketSetIterator is returned from FilterOperatorSocketSet and is used to iterate over the raw logs and unpacked data for OperatorSocketSet events raised by the ISocketRegistryV2 contract.
type ISocketRegistryV2OperatorSocketSetIterator struct {
	Event *ISocketRegistryV2OperatorSocketSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ISocketRegistryV2OperatorSocketSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ISocketRegistryV2OperatorSocketSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ISocketRegistryV2OperatorSocketSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ISocketRegistryV2OperatorSocketSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ISocketRegistryV2OperatorSocketSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ISocketRegistryV2OperatorSocketSet represents a OperatorSocketSet event raised by the ISocketRegistryV2 contract.
type ISocketRegistryV2OperatorSocketSet struct {
	Operator common.Address
	Socket   string
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterOperatorSocketSet is a free log retrieval operation binding the contract event 0x0728b43b8c8244bf835bc60bb800c6834d28d6b696427683617f8d4b0878054b.
//
// Solidity: event OperatorSocketSet(address indexed operator, string socket)
func (_ISocketRegistryV2 *ISocketRegistryV2Filterer) FilterOperatorSocketSet(opts *bind.FilterOpts, operator []common.Address) (*ISocketRegistryV2OperatorSocketSetIterator, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _ISocketRegistryV2.contract.FilterLogs(opts, "OperatorSocketSet", operatorRule)
	if err != nil {
		return nil, err
	}
	return &ISocketRegistryV2OperatorSocketSetIterator{contract: _ISocketRegistryV2.contract, event: "OperatorSocketSet", logs: logs, sub: sub}, nil
}

// WatchOperatorSocketSet is a free log subscription operation binding the contract event 0x0728b43b8c8244bf835bc60bb800c6834d28d6b696427683617f8d4b0878054b.
//
// Solidity: event OperatorSocketSet(address indexed operator, string socket)
func (_ISocketRegistryV2 *ISocketRegistryV2Filterer) WatchOperatorSocketSet(opts *bind.WatchOpts, sink chan<- *ISocketRegistryV2OperatorSocketSet, operator []common.Address) (event.Subscription, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _ISocketRegistryV2.contract.WatchLogs(opts, "OperatorSocketSet", operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ISocketRegistryV2OperatorSocketSet)
				if err := _ISocketRegistryV2.contract.UnpackLog(event, "OperatorSocketSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOperatorSocketSet is a log parse operation binding the contract event 0x0728b43b8c8244bf835bc60bb800c6834d28d6b696427683617f8d4b0878054b.
//
// Solidity: event OperatorSocketSet(address indexed operator, string socket)
func (_ISocketRegistryV2 *ISocketRegistryV2Filterer) ParseOperatorSocketSet(log types.Log) (*ISocketRegistryV2OperatorSocketSet, error) {
	event := new(ISocketRegistryV2OperatorSocketSet)
	if err := _ISocketRegistryV2.contract.UnpackLog(event, "OperatorSocketSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
