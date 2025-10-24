// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package IEigenKMSRegistrar

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

// IEigenKMSRegistrarTypesAvsConfig is an auto generated low-level Go binding around an user-defined struct.
type IEigenKMSRegistrarTypesAvsConfig struct {
	OperatorSetId uint32
}

// OperatorSet is an auto generated low-level Go binding around an user-defined struct.
type OperatorSet struct {
	Avs common.Address
	Id  uint32
}

// IEigenKMSRegistrarMetaData contains all meta data concerning the IEigenKMSRegistrar contract.
var IEigenKMSRegistrarMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"addOperatorToAllowlist\",\"inputs\":[{\"name\":\"operatorSet\",\"type\":\"tuple\",\"internalType\":\"structOperatorSet\",\"components\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"deregisterOperator\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operatorSetIds\",\"type\":\"uint32[]\",\"internalType\":\"uint32[]\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getAllowedOperators\",\"inputs\":[{\"name\":\"operatorSet\",\"type\":\"tuple\",\"internalType\":\"structOperatorSet\",\"components\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]}],\"outputs\":[{\"name\":\"\",\"type\":\"address[]\",\"internalType\":\"address[]\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAvsConfig\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structIEigenKMSRegistrarTypes.AvsConfig\",\"components\":[{\"name\":\"operatorSetId\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getOperatorSocket\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isOperatorAllowed\",\"inputs\":[{\"name\":\"operatorSet\",\"type\":\"tuple\",\"internalType\":\"structOperatorSet\",\"components\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"registerOperator\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"operatorSetIds\",\"type\":\"uint32[]\",\"internalType\":\"uint32[]\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"removeOperatorFromAllowlist\",\"inputs\":[{\"name\":\"operatorSet\",\"type\":\"tuple\",\"internalType\":\"structOperatorSet\",\"components\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setAvsConfig\",\"inputs\":[{\"name\":\"config\",\"type\":\"tuple\",\"internalType\":\"structIEigenKMSRegistrarTypes.AvsConfig\",\"components\":[{\"name\":\"operatorSetId\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsAVS\",\"inputs\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"updateSocket\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"socket\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"OperatorAddedToAllowlist\",\"inputs\":[{\"name\":\"operatorSet\",\"type\":\"tuple\",\"indexed\":true,\"internalType\":\"structOperatorSet\",\"components\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OperatorDeregistered\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"operatorSetIds\",\"type\":\"uint32[]\",\"indexed\":false,\"internalType\":\"uint32[]\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OperatorRegistered\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"operatorSetIds\",\"type\":\"uint32[]\",\"indexed\":false,\"internalType\":\"uint32[]\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OperatorRemovedFromAllowlist\",\"inputs\":[{\"name\":\"operatorSet\",\"type\":\"tuple\",\"indexed\":true,\"internalType\":\"structOperatorSet\",\"components\":[{\"name\":\"avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"id\",\"type\":\"uint32\",\"internalType\":\"uint32\"}]},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OperatorSocketSet\",\"inputs\":[{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"socket\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"KeyNotRegistered\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotAllocationManager\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OperatorAlreadyInAllowlist\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OperatorNotInAllowlist\",\"inputs\":[]}]",
}

// IEigenKMSRegistrarABI is the input ABI used to generate the binding from.
// Deprecated: Use IEigenKMSRegistrarMetaData.ABI instead.
var IEigenKMSRegistrarABI = IEigenKMSRegistrarMetaData.ABI

// IEigenKMSRegistrar is an auto generated Go binding around an Ethereum contract.
type IEigenKMSRegistrar struct {
	IEigenKMSRegistrarCaller     // Read-only binding to the contract
	IEigenKMSRegistrarTransactor // Write-only binding to the contract
	IEigenKMSRegistrarFilterer   // Log filterer for contract events
}

// IEigenKMSRegistrarCaller is an auto generated read-only Go binding around an Ethereum contract.
type IEigenKMSRegistrarCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IEigenKMSRegistrarTransactor is an auto generated write-only Go binding around an Ethereum contract.
type IEigenKMSRegistrarTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IEigenKMSRegistrarFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type IEigenKMSRegistrarFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IEigenKMSRegistrarSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type IEigenKMSRegistrarSession struct {
	Contract     *IEigenKMSRegistrar // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// IEigenKMSRegistrarCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type IEigenKMSRegistrarCallerSession struct {
	Contract *IEigenKMSRegistrarCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// IEigenKMSRegistrarTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type IEigenKMSRegistrarTransactorSession struct {
	Contract     *IEigenKMSRegistrarTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// IEigenKMSRegistrarRaw is an auto generated low-level Go binding around an Ethereum contract.
type IEigenKMSRegistrarRaw struct {
	Contract *IEigenKMSRegistrar // Generic contract binding to access the raw methods on
}

// IEigenKMSRegistrarCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type IEigenKMSRegistrarCallerRaw struct {
	Contract *IEigenKMSRegistrarCaller // Generic read-only contract binding to access the raw methods on
}

// IEigenKMSRegistrarTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type IEigenKMSRegistrarTransactorRaw struct {
	Contract *IEigenKMSRegistrarTransactor // Generic write-only contract binding to access the raw methods on
}

// NewIEigenKMSRegistrar creates a new instance of IEigenKMSRegistrar, bound to a specific deployed contract.
func NewIEigenKMSRegistrar(address common.Address, backend bind.ContractBackend) (*IEigenKMSRegistrar, error) {
	contract, err := bindIEigenKMSRegistrar(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrar{IEigenKMSRegistrarCaller: IEigenKMSRegistrarCaller{contract: contract}, IEigenKMSRegistrarTransactor: IEigenKMSRegistrarTransactor{contract: contract}, IEigenKMSRegistrarFilterer: IEigenKMSRegistrarFilterer{contract: contract}}, nil
}

// NewIEigenKMSRegistrarCaller creates a new read-only instance of IEigenKMSRegistrar, bound to a specific deployed contract.
func NewIEigenKMSRegistrarCaller(address common.Address, caller bind.ContractCaller) (*IEigenKMSRegistrarCaller, error) {
	contract, err := bindIEigenKMSRegistrar(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarCaller{contract: contract}, nil
}

// NewIEigenKMSRegistrarTransactor creates a new write-only instance of IEigenKMSRegistrar, bound to a specific deployed contract.
func NewIEigenKMSRegistrarTransactor(address common.Address, transactor bind.ContractTransactor) (*IEigenKMSRegistrarTransactor, error) {
	contract, err := bindIEigenKMSRegistrar(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarTransactor{contract: contract}, nil
}

// NewIEigenKMSRegistrarFilterer creates a new log filterer instance of IEigenKMSRegistrar, bound to a specific deployed contract.
func NewIEigenKMSRegistrarFilterer(address common.Address, filterer bind.ContractFilterer) (*IEigenKMSRegistrarFilterer, error) {
	contract, err := bindIEigenKMSRegistrar(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarFilterer{contract: contract}, nil
}

// bindIEigenKMSRegistrar binds a generic wrapper to an already deployed contract.
func bindIEigenKMSRegistrar(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := IEigenKMSRegistrarMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IEigenKMSRegistrar *IEigenKMSRegistrarRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _IEigenKMSRegistrar.Contract.IEigenKMSRegistrarCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IEigenKMSRegistrar *IEigenKMSRegistrarRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.IEigenKMSRegistrarTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IEigenKMSRegistrar *IEigenKMSRegistrarRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.IEigenKMSRegistrarTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _IEigenKMSRegistrar.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.contract.Transact(opts, method, params...)
}

// GetAllowedOperators is a free data retrieval call binding the contract method 0x7fe94e16.
//
// Solidity: function getAllowedOperators((address,uint32) operatorSet) view returns(address[])
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCaller) GetAllowedOperators(opts *bind.CallOpts, operatorSet OperatorSet) ([]common.Address, error) {
	var out []interface{}
	err := _IEigenKMSRegistrar.contract.Call(opts, &out, "getAllowedOperators", operatorSet)

	if err != nil {
		return *new([]common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new([]common.Address)).(*[]common.Address)

	return out0, err

}

// GetAllowedOperators is a free data retrieval call binding the contract method 0x7fe94e16.
//
// Solidity: function getAllowedOperators((address,uint32) operatorSet) view returns(address[])
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) GetAllowedOperators(operatorSet OperatorSet) ([]common.Address, error) {
	return _IEigenKMSRegistrar.Contract.GetAllowedOperators(&_IEigenKMSRegistrar.CallOpts, operatorSet)
}

// GetAllowedOperators is a free data retrieval call binding the contract method 0x7fe94e16.
//
// Solidity: function getAllowedOperators((address,uint32) operatorSet) view returns(address[])
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCallerSession) GetAllowedOperators(operatorSet OperatorSet) ([]common.Address, error) {
	return _IEigenKMSRegistrar.Contract.GetAllowedOperators(&_IEigenKMSRegistrar.CallOpts, operatorSet)
}

// GetAvsConfig is a free data retrieval call binding the contract method 0x41f548f0.
//
// Solidity: function getAvsConfig() view returns((uint32))
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCaller) GetAvsConfig(opts *bind.CallOpts) (IEigenKMSRegistrarTypesAvsConfig, error) {
	var out []interface{}
	err := _IEigenKMSRegistrar.contract.Call(opts, &out, "getAvsConfig")

	if err != nil {
		return *new(IEigenKMSRegistrarTypesAvsConfig), err
	}

	out0 := *abi.ConvertType(out[0], new(IEigenKMSRegistrarTypesAvsConfig)).(*IEigenKMSRegistrarTypesAvsConfig)

	return out0, err

}

// GetAvsConfig is a free data retrieval call binding the contract method 0x41f548f0.
//
// Solidity: function getAvsConfig() view returns((uint32))
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) GetAvsConfig() (IEigenKMSRegistrarTypesAvsConfig, error) {
	return _IEigenKMSRegistrar.Contract.GetAvsConfig(&_IEigenKMSRegistrar.CallOpts)
}

// GetAvsConfig is a free data retrieval call binding the contract method 0x41f548f0.
//
// Solidity: function getAvsConfig() view returns((uint32))
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCallerSession) GetAvsConfig() (IEigenKMSRegistrarTypesAvsConfig, error) {
	return _IEigenKMSRegistrar.Contract.GetAvsConfig(&_IEigenKMSRegistrar.CallOpts)
}

// GetOperatorSocket is a free data retrieval call binding the contract method 0x8481931d.
//
// Solidity: function getOperatorSocket(address operator) view returns(string)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCaller) GetOperatorSocket(opts *bind.CallOpts, operator common.Address) (string, error) {
	var out []interface{}
	err := _IEigenKMSRegistrar.contract.Call(opts, &out, "getOperatorSocket", operator)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// GetOperatorSocket is a free data retrieval call binding the contract method 0x8481931d.
//
// Solidity: function getOperatorSocket(address operator) view returns(string)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) GetOperatorSocket(operator common.Address) (string, error) {
	return _IEigenKMSRegistrar.Contract.GetOperatorSocket(&_IEigenKMSRegistrar.CallOpts, operator)
}

// GetOperatorSocket is a free data retrieval call binding the contract method 0x8481931d.
//
// Solidity: function getOperatorSocket(address operator) view returns(string)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCallerSession) GetOperatorSocket(operator common.Address) (string, error) {
	return _IEigenKMSRegistrar.Contract.GetOperatorSocket(&_IEigenKMSRegistrar.CallOpts, operator)
}

// IsOperatorAllowed is a free data retrieval call binding the contract method 0xf91ff80c.
//
// Solidity: function isOperatorAllowed((address,uint32) operatorSet, address operator) view returns(bool)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCaller) IsOperatorAllowed(opts *bind.CallOpts, operatorSet OperatorSet, operator common.Address) (bool, error) {
	var out []interface{}
	err := _IEigenKMSRegistrar.contract.Call(opts, &out, "isOperatorAllowed", operatorSet, operator)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsOperatorAllowed is a free data retrieval call binding the contract method 0xf91ff80c.
//
// Solidity: function isOperatorAllowed((address,uint32) operatorSet, address operator) view returns(bool)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) IsOperatorAllowed(operatorSet OperatorSet, operator common.Address) (bool, error) {
	return _IEigenKMSRegistrar.Contract.IsOperatorAllowed(&_IEigenKMSRegistrar.CallOpts, operatorSet, operator)
}

// IsOperatorAllowed is a free data retrieval call binding the contract method 0xf91ff80c.
//
// Solidity: function isOperatorAllowed((address,uint32) operatorSet, address operator) view returns(bool)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCallerSession) IsOperatorAllowed(operatorSet OperatorSet, operator common.Address) (bool, error) {
	return _IEigenKMSRegistrar.Contract.IsOperatorAllowed(&_IEigenKMSRegistrar.CallOpts, operatorSet, operator)
}

// SupportsAVS is a free data retrieval call binding the contract method 0xb5265787.
//
// Solidity: function supportsAVS(address avs) view returns(bool)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCaller) SupportsAVS(opts *bind.CallOpts, avs common.Address) (bool, error) {
	var out []interface{}
	err := _IEigenKMSRegistrar.contract.Call(opts, &out, "supportsAVS", avs)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsAVS is a free data retrieval call binding the contract method 0xb5265787.
//
// Solidity: function supportsAVS(address avs) view returns(bool)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) SupportsAVS(avs common.Address) (bool, error) {
	return _IEigenKMSRegistrar.Contract.SupportsAVS(&_IEigenKMSRegistrar.CallOpts, avs)
}

// SupportsAVS is a free data retrieval call binding the contract method 0xb5265787.
//
// Solidity: function supportsAVS(address avs) view returns(bool)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarCallerSession) SupportsAVS(avs common.Address) (bool, error) {
	return _IEigenKMSRegistrar.Contract.SupportsAVS(&_IEigenKMSRegistrar.CallOpts, avs)
}

// AddOperatorToAllowlist is a paid mutator transaction binding the contract method 0x1017873a.
//
// Solidity: function addOperatorToAllowlist((address,uint32) operatorSet, address operator) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactor) AddOperatorToAllowlist(opts *bind.TransactOpts, operatorSet OperatorSet, operator common.Address) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.contract.Transact(opts, "addOperatorToAllowlist", operatorSet, operator)
}

// AddOperatorToAllowlist is a paid mutator transaction binding the contract method 0x1017873a.
//
// Solidity: function addOperatorToAllowlist((address,uint32) operatorSet, address operator) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) AddOperatorToAllowlist(operatorSet OperatorSet, operator common.Address) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.AddOperatorToAllowlist(&_IEigenKMSRegistrar.TransactOpts, operatorSet, operator)
}

// AddOperatorToAllowlist is a paid mutator transaction binding the contract method 0x1017873a.
//
// Solidity: function addOperatorToAllowlist((address,uint32) operatorSet, address operator) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorSession) AddOperatorToAllowlist(operatorSet OperatorSet, operator common.Address) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.AddOperatorToAllowlist(&_IEigenKMSRegistrar.TransactOpts, operatorSet, operator)
}

// DeregisterOperator is a paid mutator transaction binding the contract method 0x303ca956.
//
// Solidity: function deregisterOperator(address operator, address avs, uint32[] operatorSetIds) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactor) DeregisterOperator(opts *bind.TransactOpts, operator common.Address, avs common.Address, operatorSetIds []uint32) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.contract.Transact(opts, "deregisterOperator", operator, avs, operatorSetIds)
}

// DeregisterOperator is a paid mutator transaction binding the contract method 0x303ca956.
//
// Solidity: function deregisterOperator(address operator, address avs, uint32[] operatorSetIds) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) DeregisterOperator(operator common.Address, avs common.Address, operatorSetIds []uint32) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.DeregisterOperator(&_IEigenKMSRegistrar.TransactOpts, operator, avs, operatorSetIds)
}

// DeregisterOperator is a paid mutator transaction binding the contract method 0x303ca956.
//
// Solidity: function deregisterOperator(address operator, address avs, uint32[] operatorSetIds) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorSession) DeregisterOperator(operator common.Address, avs common.Address, operatorSetIds []uint32) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.DeregisterOperator(&_IEigenKMSRegistrar.TransactOpts, operator, avs, operatorSetIds)
}

// RegisterOperator is a paid mutator transaction binding the contract method 0xc63fd502.
//
// Solidity: function registerOperator(address operator, address avs, uint32[] operatorSetIds, bytes data) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactor) RegisterOperator(opts *bind.TransactOpts, operator common.Address, avs common.Address, operatorSetIds []uint32, data []byte) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.contract.Transact(opts, "registerOperator", operator, avs, operatorSetIds, data)
}

// RegisterOperator is a paid mutator transaction binding the contract method 0xc63fd502.
//
// Solidity: function registerOperator(address operator, address avs, uint32[] operatorSetIds, bytes data) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) RegisterOperator(operator common.Address, avs common.Address, operatorSetIds []uint32, data []byte) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.RegisterOperator(&_IEigenKMSRegistrar.TransactOpts, operator, avs, operatorSetIds, data)
}

// RegisterOperator is a paid mutator transaction binding the contract method 0xc63fd502.
//
// Solidity: function registerOperator(address operator, address avs, uint32[] operatorSetIds, bytes data) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorSession) RegisterOperator(operator common.Address, avs common.Address, operatorSetIds []uint32, data []byte) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.RegisterOperator(&_IEigenKMSRegistrar.TransactOpts, operator, avs, operatorSetIds, data)
}

// RemoveOperatorFromAllowlist is a paid mutator transaction binding the contract method 0x0a4d3d29.
//
// Solidity: function removeOperatorFromAllowlist((address,uint32) operatorSet, address operator) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactor) RemoveOperatorFromAllowlist(opts *bind.TransactOpts, operatorSet OperatorSet, operator common.Address) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.contract.Transact(opts, "removeOperatorFromAllowlist", operatorSet, operator)
}

// RemoveOperatorFromAllowlist is a paid mutator transaction binding the contract method 0x0a4d3d29.
//
// Solidity: function removeOperatorFromAllowlist((address,uint32) operatorSet, address operator) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) RemoveOperatorFromAllowlist(operatorSet OperatorSet, operator common.Address) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.RemoveOperatorFromAllowlist(&_IEigenKMSRegistrar.TransactOpts, operatorSet, operator)
}

// RemoveOperatorFromAllowlist is a paid mutator transaction binding the contract method 0x0a4d3d29.
//
// Solidity: function removeOperatorFromAllowlist((address,uint32) operatorSet, address operator) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorSession) RemoveOperatorFromAllowlist(operatorSet OperatorSet, operator common.Address) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.RemoveOperatorFromAllowlist(&_IEigenKMSRegistrar.TransactOpts, operatorSet, operator)
}

// SetAvsConfig is a paid mutator transaction binding the contract method 0xee491b4b.
//
// Solidity: function setAvsConfig((uint32) config) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactor) SetAvsConfig(opts *bind.TransactOpts, config IEigenKMSRegistrarTypesAvsConfig) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.contract.Transact(opts, "setAvsConfig", config)
}

// SetAvsConfig is a paid mutator transaction binding the contract method 0xee491b4b.
//
// Solidity: function setAvsConfig((uint32) config) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) SetAvsConfig(config IEigenKMSRegistrarTypesAvsConfig) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.SetAvsConfig(&_IEigenKMSRegistrar.TransactOpts, config)
}

// SetAvsConfig is a paid mutator transaction binding the contract method 0xee491b4b.
//
// Solidity: function setAvsConfig((uint32) config) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorSession) SetAvsConfig(config IEigenKMSRegistrarTypesAvsConfig) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.SetAvsConfig(&_IEigenKMSRegistrar.TransactOpts, config)
}

// UpdateSocket is a paid mutator transaction binding the contract method 0x6591666a.
//
// Solidity: function updateSocket(address operator, string socket) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactor) UpdateSocket(opts *bind.TransactOpts, operator common.Address, socket string) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.contract.Transact(opts, "updateSocket", operator, socket)
}

// UpdateSocket is a paid mutator transaction binding the contract method 0x6591666a.
//
// Solidity: function updateSocket(address operator, string socket) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarSession) UpdateSocket(operator common.Address, socket string) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.UpdateSocket(&_IEigenKMSRegistrar.TransactOpts, operator, socket)
}

// UpdateSocket is a paid mutator transaction binding the contract method 0x6591666a.
//
// Solidity: function updateSocket(address operator, string socket) returns()
func (_IEigenKMSRegistrar *IEigenKMSRegistrarTransactorSession) UpdateSocket(operator common.Address, socket string) (*types.Transaction, error) {
	return _IEigenKMSRegistrar.Contract.UpdateSocket(&_IEigenKMSRegistrar.TransactOpts, operator, socket)
}

// IEigenKMSRegistrarOperatorAddedToAllowlistIterator is returned from FilterOperatorAddedToAllowlist and is used to iterate over the raw logs and unpacked data for OperatorAddedToAllowlist events raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorAddedToAllowlistIterator struct {
	Event *IEigenKMSRegistrarOperatorAddedToAllowlist // Event containing the contract specifics and raw log

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
func (it *IEigenKMSRegistrarOperatorAddedToAllowlistIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(IEigenKMSRegistrarOperatorAddedToAllowlist)
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
		it.Event = new(IEigenKMSRegistrarOperatorAddedToAllowlist)
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
func (it *IEigenKMSRegistrarOperatorAddedToAllowlistIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *IEigenKMSRegistrarOperatorAddedToAllowlistIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// IEigenKMSRegistrarOperatorAddedToAllowlist represents a OperatorAddedToAllowlist event raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorAddedToAllowlist struct {
	OperatorSet OperatorSet
	Operator    common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterOperatorAddedToAllowlist is a free log retrieval operation binding the contract event 0xfe795219771c42bdbb61ef308cc2b33e1e35b35a3364499b99b2ec2287f20c8c.
//
// Solidity: event OperatorAddedToAllowlist((address,uint32) indexed operatorSet, address indexed operator)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) FilterOperatorAddedToAllowlist(opts *bind.FilterOpts, operatorSet []OperatorSet, operator []common.Address) (*IEigenKMSRegistrarOperatorAddedToAllowlistIterator, error) {

	var operatorSetRule []interface{}
	for _, operatorSetItem := range operatorSet {
		operatorSetRule = append(operatorSetRule, operatorSetItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.FilterLogs(opts, "OperatorAddedToAllowlist", operatorSetRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarOperatorAddedToAllowlistIterator{contract: _IEigenKMSRegistrar.contract, event: "OperatorAddedToAllowlist", logs: logs, sub: sub}, nil
}

// WatchOperatorAddedToAllowlist is a free log subscription operation binding the contract event 0xfe795219771c42bdbb61ef308cc2b33e1e35b35a3364499b99b2ec2287f20c8c.
//
// Solidity: event OperatorAddedToAllowlist((address,uint32) indexed operatorSet, address indexed operator)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) WatchOperatorAddedToAllowlist(opts *bind.WatchOpts, sink chan<- *IEigenKMSRegistrarOperatorAddedToAllowlist, operatorSet []OperatorSet, operator []common.Address) (event.Subscription, error) {

	var operatorSetRule []interface{}
	for _, operatorSetItem := range operatorSet {
		operatorSetRule = append(operatorSetRule, operatorSetItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.WatchLogs(opts, "OperatorAddedToAllowlist", operatorSetRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(IEigenKMSRegistrarOperatorAddedToAllowlist)
				if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorAddedToAllowlist", log); err != nil {
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

// ParseOperatorAddedToAllowlist is a log parse operation binding the contract event 0xfe795219771c42bdbb61ef308cc2b33e1e35b35a3364499b99b2ec2287f20c8c.
//
// Solidity: event OperatorAddedToAllowlist((address,uint32) indexed operatorSet, address indexed operator)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) ParseOperatorAddedToAllowlist(log types.Log) (*IEigenKMSRegistrarOperatorAddedToAllowlist, error) {
	event := new(IEigenKMSRegistrarOperatorAddedToAllowlist)
	if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorAddedToAllowlist", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// IEigenKMSRegistrarOperatorDeregisteredIterator is returned from FilterOperatorDeregistered and is used to iterate over the raw logs and unpacked data for OperatorDeregistered events raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorDeregisteredIterator struct {
	Event *IEigenKMSRegistrarOperatorDeregistered // Event containing the contract specifics and raw log

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
func (it *IEigenKMSRegistrarOperatorDeregisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(IEigenKMSRegistrarOperatorDeregistered)
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
		it.Event = new(IEigenKMSRegistrarOperatorDeregistered)
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
func (it *IEigenKMSRegistrarOperatorDeregisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *IEigenKMSRegistrarOperatorDeregisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// IEigenKMSRegistrarOperatorDeregistered represents a OperatorDeregistered event raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorDeregistered struct {
	Operator       common.Address
	OperatorSetIds []uint32
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterOperatorDeregistered is a free log retrieval operation binding the contract event 0xf8aaad08ee23b49c9bb44e3bca6c7efa43442fc4281245a7f2475aa2632718d1.
//
// Solidity: event OperatorDeregistered(address indexed operator, uint32[] operatorSetIds)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) FilterOperatorDeregistered(opts *bind.FilterOpts, operator []common.Address) (*IEigenKMSRegistrarOperatorDeregisteredIterator, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.FilterLogs(opts, "OperatorDeregistered", operatorRule)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarOperatorDeregisteredIterator{contract: _IEigenKMSRegistrar.contract, event: "OperatorDeregistered", logs: logs, sub: sub}, nil
}

// WatchOperatorDeregistered is a free log subscription operation binding the contract event 0xf8aaad08ee23b49c9bb44e3bca6c7efa43442fc4281245a7f2475aa2632718d1.
//
// Solidity: event OperatorDeregistered(address indexed operator, uint32[] operatorSetIds)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) WatchOperatorDeregistered(opts *bind.WatchOpts, sink chan<- *IEigenKMSRegistrarOperatorDeregistered, operator []common.Address) (event.Subscription, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.WatchLogs(opts, "OperatorDeregistered", operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(IEigenKMSRegistrarOperatorDeregistered)
				if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorDeregistered", log); err != nil {
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

// ParseOperatorDeregistered is a log parse operation binding the contract event 0xf8aaad08ee23b49c9bb44e3bca6c7efa43442fc4281245a7f2475aa2632718d1.
//
// Solidity: event OperatorDeregistered(address indexed operator, uint32[] operatorSetIds)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) ParseOperatorDeregistered(log types.Log) (*IEigenKMSRegistrarOperatorDeregistered, error) {
	event := new(IEigenKMSRegistrarOperatorDeregistered)
	if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorDeregistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// IEigenKMSRegistrarOperatorRegisteredIterator is returned from FilterOperatorRegistered and is used to iterate over the raw logs and unpacked data for OperatorRegistered events raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorRegisteredIterator struct {
	Event *IEigenKMSRegistrarOperatorRegistered // Event containing the contract specifics and raw log

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
func (it *IEigenKMSRegistrarOperatorRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(IEigenKMSRegistrarOperatorRegistered)
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
		it.Event = new(IEigenKMSRegistrarOperatorRegistered)
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
func (it *IEigenKMSRegistrarOperatorRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *IEigenKMSRegistrarOperatorRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// IEigenKMSRegistrarOperatorRegistered represents a OperatorRegistered event raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorRegistered struct {
	Operator       common.Address
	OperatorSetIds []uint32
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterOperatorRegistered is a free log retrieval operation binding the contract event 0x9efdc3d07eb312e06bf36ea85db02aec96817d7c7421f919027b240eaf34035d.
//
// Solidity: event OperatorRegistered(address indexed operator, uint32[] operatorSetIds)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) FilterOperatorRegistered(opts *bind.FilterOpts, operator []common.Address) (*IEigenKMSRegistrarOperatorRegisteredIterator, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.FilterLogs(opts, "OperatorRegistered", operatorRule)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarOperatorRegisteredIterator{contract: _IEigenKMSRegistrar.contract, event: "OperatorRegistered", logs: logs, sub: sub}, nil
}

// WatchOperatorRegistered is a free log subscription operation binding the contract event 0x9efdc3d07eb312e06bf36ea85db02aec96817d7c7421f919027b240eaf34035d.
//
// Solidity: event OperatorRegistered(address indexed operator, uint32[] operatorSetIds)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) WatchOperatorRegistered(opts *bind.WatchOpts, sink chan<- *IEigenKMSRegistrarOperatorRegistered, operator []common.Address) (event.Subscription, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.WatchLogs(opts, "OperatorRegistered", operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(IEigenKMSRegistrarOperatorRegistered)
				if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorRegistered", log); err != nil {
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

// ParseOperatorRegistered is a log parse operation binding the contract event 0x9efdc3d07eb312e06bf36ea85db02aec96817d7c7421f919027b240eaf34035d.
//
// Solidity: event OperatorRegistered(address indexed operator, uint32[] operatorSetIds)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) ParseOperatorRegistered(log types.Log) (*IEigenKMSRegistrarOperatorRegistered, error) {
	event := new(IEigenKMSRegistrarOperatorRegistered)
	if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator is returned from FilterOperatorRemovedFromAllowlist and is used to iterate over the raw logs and unpacked data for OperatorRemovedFromAllowlist events raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator struct {
	Event *IEigenKMSRegistrarOperatorRemovedFromAllowlist // Event containing the contract specifics and raw log

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
func (it *IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(IEigenKMSRegistrarOperatorRemovedFromAllowlist)
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
		it.Event = new(IEigenKMSRegistrarOperatorRemovedFromAllowlist)
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
func (it *IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// IEigenKMSRegistrarOperatorRemovedFromAllowlist represents a OperatorRemovedFromAllowlist event raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorRemovedFromAllowlist struct {
	OperatorSet OperatorSet
	Operator    common.Address
	Raw         types.Log // Blockchain specific contextual infos
}

// FilterOperatorRemovedFromAllowlist is a free log retrieval operation binding the contract event 0x533bf6e1348e64eb9448930dece3436586c031d36722adbc7ccb479809128806.
//
// Solidity: event OperatorRemovedFromAllowlist((address,uint32) indexed operatorSet, address indexed operator)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) FilterOperatorRemovedFromAllowlist(opts *bind.FilterOpts, operatorSet []OperatorSet, operator []common.Address) (*IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator, error) {

	var operatorSetRule []interface{}
	for _, operatorSetItem := range operatorSet {
		operatorSetRule = append(operatorSetRule, operatorSetItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.FilterLogs(opts, "OperatorRemovedFromAllowlist", operatorSetRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarOperatorRemovedFromAllowlistIterator{contract: _IEigenKMSRegistrar.contract, event: "OperatorRemovedFromAllowlist", logs: logs, sub: sub}, nil
}

// WatchOperatorRemovedFromAllowlist is a free log subscription operation binding the contract event 0x533bf6e1348e64eb9448930dece3436586c031d36722adbc7ccb479809128806.
//
// Solidity: event OperatorRemovedFromAllowlist((address,uint32) indexed operatorSet, address indexed operator)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) WatchOperatorRemovedFromAllowlist(opts *bind.WatchOpts, sink chan<- *IEigenKMSRegistrarOperatorRemovedFromAllowlist, operatorSet []OperatorSet, operator []common.Address) (event.Subscription, error) {

	var operatorSetRule []interface{}
	for _, operatorSetItem := range operatorSet {
		operatorSetRule = append(operatorSetRule, operatorSetItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.WatchLogs(opts, "OperatorRemovedFromAllowlist", operatorSetRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(IEigenKMSRegistrarOperatorRemovedFromAllowlist)
				if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorRemovedFromAllowlist", log); err != nil {
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

// ParseOperatorRemovedFromAllowlist is a log parse operation binding the contract event 0x533bf6e1348e64eb9448930dece3436586c031d36722adbc7ccb479809128806.
//
// Solidity: event OperatorRemovedFromAllowlist((address,uint32) indexed operatorSet, address indexed operator)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) ParseOperatorRemovedFromAllowlist(log types.Log) (*IEigenKMSRegistrarOperatorRemovedFromAllowlist, error) {
	event := new(IEigenKMSRegistrarOperatorRemovedFromAllowlist)
	if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorRemovedFromAllowlist", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// IEigenKMSRegistrarOperatorSocketSetIterator is returned from FilterOperatorSocketSet and is used to iterate over the raw logs and unpacked data for OperatorSocketSet events raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorSocketSetIterator struct {
	Event *IEigenKMSRegistrarOperatorSocketSet // Event containing the contract specifics and raw log

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
func (it *IEigenKMSRegistrarOperatorSocketSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(IEigenKMSRegistrarOperatorSocketSet)
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
		it.Event = new(IEigenKMSRegistrarOperatorSocketSet)
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
func (it *IEigenKMSRegistrarOperatorSocketSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *IEigenKMSRegistrarOperatorSocketSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// IEigenKMSRegistrarOperatorSocketSet represents a OperatorSocketSet event raised by the IEigenKMSRegistrar contract.
type IEigenKMSRegistrarOperatorSocketSet struct {
	Operator common.Address
	Socket   string
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterOperatorSocketSet is a free log retrieval operation binding the contract event 0x0728b43b8c8244bf835bc60bb800c6834d28d6b696427683617f8d4b0878054b.
//
// Solidity: event OperatorSocketSet(address indexed operator, string socket)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) FilterOperatorSocketSet(opts *bind.FilterOpts, operator []common.Address) (*IEigenKMSRegistrarOperatorSocketSetIterator, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.FilterLogs(opts, "OperatorSocketSet", operatorRule)
	if err != nil {
		return nil, err
	}
	return &IEigenKMSRegistrarOperatorSocketSetIterator{contract: _IEigenKMSRegistrar.contract, event: "OperatorSocketSet", logs: logs, sub: sub}, nil
}

// WatchOperatorSocketSet is a free log subscription operation binding the contract event 0x0728b43b8c8244bf835bc60bb800c6834d28d6b696427683617f8d4b0878054b.
//
// Solidity: event OperatorSocketSet(address indexed operator, string socket)
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) WatchOperatorSocketSet(opts *bind.WatchOpts, sink chan<- *IEigenKMSRegistrarOperatorSocketSet, operator []common.Address) (event.Subscription, error) {

	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _IEigenKMSRegistrar.contract.WatchLogs(opts, "OperatorSocketSet", operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(IEigenKMSRegistrarOperatorSocketSet)
				if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorSocketSet", log); err != nil {
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
func (_IEigenKMSRegistrar *IEigenKMSRegistrarFilterer) ParseOperatorSocketSet(log types.Log) (*IEigenKMSRegistrarOperatorSocketSet, error) {
	event := new(IEigenKMSRegistrarOperatorSocketSet)
	if err := _IEigenKMSRegistrar.contract.UnpackLog(event, "OperatorSocketSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
