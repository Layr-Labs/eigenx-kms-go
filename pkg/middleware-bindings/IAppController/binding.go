// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package IAppController

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

// IAppControllerAppRelease is an auto generated low-level Go binding around an user-defined struct.
type IAppControllerAppRelease struct {
	RmsRelease      IAppControllerRmsRelease
	PublicEnv       []byte
	EncryptedEnv    []byte
	ContainerPolicy IAppControllerContainerPolicy
}

// IAppControllerArtifact is an auto generated low-level Go binding around an user-defined struct.
type IAppControllerArtifact struct {
	Digest [32]byte
}

// IAppControllerContainerPolicy is an auto generated low-level Go binding around an user-defined struct.
type IAppControllerContainerPolicy struct {
	Args              []string
	CmdOverride       []string
	EnvKeys           []string
	EnvValues         []string
	EnvOverrideKeys   []string
	EnvOverrideValues []string
	RestartPolicy     string
}

// IAppControllerRmsRelease is an auto generated low-level Go binding around an user-defined struct.
type IAppControllerRmsRelease struct {
	Artifacts []IAppControllerArtifact
}

// IAppControllerMetaData contains all meta data concerning the IAppController contract.
var IAppControllerMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"getAppCreator\",\"inputs\":[{\"name\":\"app\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAppLatestReleaseBlockNumber\",\"inputs\":[{\"name\":\"app\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAppOperatorSetId\",\"inputs\":[{\"name\":\"app\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAppStatus\",\"inputs\":[{\"name\":\"app\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"event\",\"name\":\"AppUpgraded\",\"inputs\":[{\"name\":\"app\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"rmsReleaseId\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"release\",\"type\":\"tuple\",\"indexed\":false,\"internalType\":\"structIAppController.AppRelease\",\"components\":[{\"name\":\"rmsRelease\",\"type\":\"tuple\",\"internalType\":\"structIAppController.RmsRelease\",\"components\":[{\"name\":\"artifacts\",\"type\":\"tuple[]\",\"internalType\":\"structIAppController.Artifact[]\",\"components\":[{\"name\":\"digest\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}]},{\"name\":\"publicEnv\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"encryptedEnv\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"containerPolicy\",\"type\":\"tuple\",\"internalType\":\"structIAppController.ContainerPolicy\",\"components\":[{\"name\":\"args\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"cmdOverride\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"envKeys\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"envValues\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"envOverrideKeys\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"envOverrideValues\",\"type\":\"string[]\",\"internalType\":\"string[]\"},{\"name\":\"restartPolicy\",\"type\":\"string\",\"internalType\":\"string\"}]}]}],\"anonymous\":false}]",
}

// IAppControllerABI is the input ABI used to generate the binding from.
// Deprecated: Use IAppControllerMetaData.ABI instead.
var IAppControllerABI = IAppControllerMetaData.ABI

// IAppController is an auto generated Go binding around an Ethereum contract.
type IAppController struct {
	IAppControllerCaller     // Read-only binding to the contract
	IAppControllerTransactor // Write-only binding to the contract
	IAppControllerFilterer   // Log filterer for contract events
}

// IAppControllerCaller is an auto generated read-only Go binding around an Ethereum contract.
type IAppControllerCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IAppControllerTransactor is an auto generated write-only Go binding around an Ethereum contract.
type IAppControllerTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IAppControllerFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type IAppControllerFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IAppControllerSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type IAppControllerSession struct {
	Contract     *IAppController   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// IAppControllerCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type IAppControllerCallerSession struct {
	Contract *IAppControllerCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// IAppControllerTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type IAppControllerTransactorSession struct {
	Contract     *IAppControllerTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// IAppControllerRaw is an auto generated low-level Go binding around an Ethereum contract.
type IAppControllerRaw struct {
	Contract *IAppController // Generic contract binding to access the raw methods on
}

// IAppControllerCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type IAppControllerCallerRaw struct {
	Contract *IAppControllerCaller // Generic read-only contract binding to access the raw methods on
}

// IAppControllerTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type IAppControllerTransactorRaw struct {
	Contract *IAppControllerTransactor // Generic write-only contract binding to access the raw methods on
}

// NewIAppController creates a new instance of IAppController, bound to a specific deployed contract.
func NewIAppController(address common.Address, backend bind.ContractBackend) (*IAppController, error) {
	contract, err := bindIAppController(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &IAppController{IAppControllerCaller: IAppControllerCaller{contract: contract}, IAppControllerTransactor: IAppControllerTransactor{contract: contract}, IAppControllerFilterer: IAppControllerFilterer{contract: contract}}, nil
}

// NewIAppControllerCaller creates a new read-only instance of IAppController, bound to a specific deployed contract.
func NewIAppControllerCaller(address common.Address, caller bind.ContractCaller) (*IAppControllerCaller, error) {
	contract, err := bindIAppController(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &IAppControllerCaller{contract: contract}, nil
}

// NewIAppControllerTransactor creates a new write-only instance of IAppController, bound to a specific deployed contract.
func NewIAppControllerTransactor(address common.Address, transactor bind.ContractTransactor) (*IAppControllerTransactor, error) {
	contract, err := bindIAppController(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &IAppControllerTransactor{contract: contract}, nil
}

// NewIAppControllerFilterer creates a new log filterer instance of IAppController, bound to a specific deployed contract.
func NewIAppControllerFilterer(address common.Address, filterer bind.ContractFilterer) (*IAppControllerFilterer, error) {
	contract, err := bindIAppController(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &IAppControllerFilterer{contract: contract}, nil
}

// bindIAppController binds a generic wrapper to an already deployed contract.
func bindIAppController(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := IAppControllerMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IAppController *IAppControllerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _IAppController.Contract.IAppControllerCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IAppController *IAppControllerRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IAppController.Contract.IAppControllerTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IAppController *IAppControllerRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IAppController.Contract.IAppControllerTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IAppController *IAppControllerCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _IAppController.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IAppController *IAppControllerTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IAppController.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IAppController *IAppControllerTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IAppController.Contract.contract.Transact(opts, method, params...)
}

// GetAppCreator is a free data retrieval call binding the contract method 0x67962d48.
//
// Solidity: function getAppCreator(address app) view returns(address)
func (_IAppController *IAppControllerCaller) GetAppCreator(opts *bind.CallOpts, app common.Address) (common.Address, error) {
	var out []interface{}
	err := _IAppController.contract.Call(opts, &out, "getAppCreator", app)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetAppCreator is a free data retrieval call binding the contract method 0x67962d48.
//
// Solidity: function getAppCreator(address app) view returns(address)
func (_IAppController *IAppControllerSession) GetAppCreator(app common.Address) (common.Address, error) {
	return _IAppController.Contract.GetAppCreator(&_IAppController.CallOpts, app)
}

// GetAppCreator is a free data retrieval call binding the contract method 0x67962d48.
//
// Solidity: function getAppCreator(address app) view returns(address)
func (_IAppController *IAppControllerCallerSession) GetAppCreator(app common.Address) (common.Address, error) {
	return _IAppController.Contract.GetAppCreator(&_IAppController.CallOpts, app)
}

// GetAppLatestReleaseBlockNumber is a free data retrieval call binding the contract method 0x9ffbdce6.
//
// Solidity: function getAppLatestReleaseBlockNumber(address app) view returns(uint32)
func (_IAppController *IAppControllerCaller) GetAppLatestReleaseBlockNumber(opts *bind.CallOpts, app common.Address) (uint32, error) {
	var out []interface{}
	err := _IAppController.contract.Call(opts, &out, "getAppLatestReleaseBlockNumber", app)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetAppLatestReleaseBlockNumber is a free data retrieval call binding the contract method 0x9ffbdce6.
//
// Solidity: function getAppLatestReleaseBlockNumber(address app) view returns(uint32)
func (_IAppController *IAppControllerSession) GetAppLatestReleaseBlockNumber(app common.Address) (uint32, error) {
	return _IAppController.Contract.GetAppLatestReleaseBlockNumber(&_IAppController.CallOpts, app)
}

// GetAppLatestReleaseBlockNumber is a free data retrieval call binding the contract method 0x9ffbdce6.
//
// Solidity: function getAppLatestReleaseBlockNumber(address app) view returns(uint32)
func (_IAppController *IAppControllerCallerSession) GetAppLatestReleaseBlockNumber(app common.Address) (uint32, error) {
	return _IAppController.Contract.GetAppLatestReleaseBlockNumber(&_IAppController.CallOpts, app)
}

// GetAppOperatorSetId is a free data retrieval call binding the contract method 0x6eb2099f.
//
// Solidity: function getAppOperatorSetId(address app) view returns(uint32)
func (_IAppController *IAppControllerCaller) GetAppOperatorSetId(opts *bind.CallOpts, app common.Address) (uint32, error) {
	var out []interface{}
	err := _IAppController.contract.Call(opts, &out, "getAppOperatorSetId", app)

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// GetAppOperatorSetId is a free data retrieval call binding the contract method 0x6eb2099f.
//
// Solidity: function getAppOperatorSetId(address app) view returns(uint32)
func (_IAppController *IAppControllerSession) GetAppOperatorSetId(app common.Address) (uint32, error) {
	return _IAppController.Contract.GetAppOperatorSetId(&_IAppController.CallOpts, app)
}

// GetAppOperatorSetId is a free data retrieval call binding the contract method 0x6eb2099f.
//
// Solidity: function getAppOperatorSetId(address app) view returns(uint32)
func (_IAppController *IAppControllerCallerSession) GetAppOperatorSetId(app common.Address) (uint32, error) {
	return _IAppController.Contract.GetAppOperatorSetId(&_IAppController.CallOpts, app)
}

// GetAppStatus is a free data retrieval call binding the contract method 0xd5aae178.
//
// Solidity: function getAppStatus(address app) view returns(uint8)
func (_IAppController *IAppControllerCaller) GetAppStatus(opts *bind.CallOpts, app common.Address) (uint8, error) {
	var out []interface{}
	err := _IAppController.contract.Call(opts, &out, "getAppStatus", app)

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// GetAppStatus is a free data retrieval call binding the contract method 0xd5aae178.
//
// Solidity: function getAppStatus(address app) view returns(uint8)
func (_IAppController *IAppControllerSession) GetAppStatus(app common.Address) (uint8, error) {
	return _IAppController.Contract.GetAppStatus(&_IAppController.CallOpts, app)
}

// GetAppStatus is a free data retrieval call binding the contract method 0xd5aae178.
//
// Solidity: function getAppStatus(address app) view returns(uint8)
func (_IAppController *IAppControllerCallerSession) GetAppStatus(app common.Address) (uint8, error) {
	return _IAppController.Contract.GetAppStatus(&_IAppController.CallOpts, app)
}

// IAppControllerAppUpgradedIterator is returned from FilterAppUpgraded and is used to iterate over the raw logs and unpacked data for AppUpgraded events raised by the IAppController contract.
type IAppControllerAppUpgradedIterator struct {
	Event *IAppControllerAppUpgraded // Event containing the contract specifics and raw log

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
func (it *IAppControllerAppUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(IAppControllerAppUpgraded)
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
		it.Event = new(IAppControllerAppUpgraded)
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
func (it *IAppControllerAppUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *IAppControllerAppUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// IAppControllerAppUpgraded represents a AppUpgraded event raised by the IAppController contract.
type IAppControllerAppUpgraded struct {
	App          common.Address
	RmsReleaseId [32]byte
	Release      IAppControllerAppRelease
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterAppUpgraded is a free log retrieval operation binding the contract event 0x04f54fa9cd66cebd05b2cf1840dbd941d04e00ecd339e4f2067272520957d052.
//
// Solidity: event AppUpgraded(address indexed app, bytes32 rmsReleaseId, (((bytes32)[]),bytes,bytes,(string[],string[],string[],string[],string[],string[],string)) release)
func (_IAppController *IAppControllerFilterer) FilterAppUpgraded(opts *bind.FilterOpts, app []common.Address) (*IAppControllerAppUpgradedIterator, error) {

	var appRule []interface{}
	for _, appItem := range app {
		appRule = append(appRule, appItem)
	}

	logs, sub, err := _IAppController.contract.FilterLogs(opts, "AppUpgraded", appRule)
	if err != nil {
		return nil, err
	}
	return &IAppControllerAppUpgradedIterator{contract: _IAppController.contract, event: "AppUpgraded", logs: logs, sub: sub}, nil
}

// WatchAppUpgraded is a free log subscription operation binding the contract event 0x04f54fa9cd66cebd05b2cf1840dbd941d04e00ecd339e4f2067272520957d052.
//
// Solidity: event AppUpgraded(address indexed app, bytes32 rmsReleaseId, (((bytes32)[]),bytes,bytes,(string[],string[],string[],string[],string[],string[],string)) release)
func (_IAppController *IAppControllerFilterer) WatchAppUpgraded(opts *bind.WatchOpts, sink chan<- *IAppControllerAppUpgraded, app []common.Address) (event.Subscription, error) {

	var appRule []interface{}
	for _, appItem := range app {
		appRule = append(appRule, appItem)
	}

	logs, sub, err := _IAppController.contract.WatchLogs(opts, "AppUpgraded", appRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(IAppControllerAppUpgraded)
				if err := _IAppController.contract.UnpackLog(event, "AppUpgraded", log); err != nil {
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

// ParseAppUpgraded is a log parse operation binding the contract event 0x04f54fa9cd66cebd05b2cf1840dbd941d04e00ecd339e4f2067272520957d052.
//
// Solidity: event AppUpgraded(address indexed app, bytes32 rmsReleaseId, (((bytes32)[]),bytes,bytes,(string[],string[],string[],string[],string[],string[],string)) release)
func (_IAppController *IAppControllerFilterer) ParseAppUpgraded(log types.Log) (*IAppControllerAppUpgraded, error) {
	event := new(IAppControllerAppUpgraded)
	if err := _IAppController.contract.UnpackLog(event, "AppUpgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
