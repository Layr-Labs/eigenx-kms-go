// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package EigenKMSCommitmentRegistry

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

// EigenKMSCommitmentRegistryMetaData contains all meta data concerning the EigenKMSCommitmentRegistry contract.
var EigenKMSCommitmentRegistryMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"commitments\",\"inputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"ackMerkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"submittedAt\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getCommitment\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"ackMerkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"submittedAt\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"proveEquivocation\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"dealer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"ack1\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"proof1\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"ack2\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"proof2\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}],\"outputs\":[],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"submitCommitment\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"_commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_ackMerkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"CommitmentSubmitted\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"indexed\":true,\"internalType\":\"uint64\"},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"ackMerkleRoot\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"}],\"anonymous\":false}]",
	Bin: "0x6080604052348015600e575f5ffd5b506105588061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806356a62d0f1461004e5780639fee311e146100d1578063d50b3748146100e6578063fd935eb4146100f9575b5f5ffd5b6100b261005c36600461034a565b67ffffffffffffffff82165f908152602081815260408083206001600160a01b03851684528252918290208251606081018452815480825260018301549382018490526002909201549301839052919250925092565b6040805193845260208401929092529082015260600160405180910390f35b6100e46100df366004610401565b61012f565b005b6100e46100f43660046104f2565b61018b565b6100b261010736600461034a565b5f60208181529281526040808220909352908152208054600182015460029092015490919083565b60405162461bcd60e51b815260206004820152602660248201527f4e6f7420696d706c656d656e746564202d20726573657276656420666f7220506044820152650d0c2e6ca40760d31b60648201526084015b60405180910390fd5b816101d85760405162461bcd60e51b815260206004820152601760248201527f496e76616c696420636f6d6d69746d656e7420686173680000000000000000006044820152606401610182565b8061021b5760405162461bcd60e51b8152602060048201526013602482015272125b9d985b1a59081b595c9adb19481c9bdbdd606a1b6044820152606401610182565b67ffffffffffffffff83165f908152602081815260408083203384529091529020541561028a5760405162461bcd60e51b815260206004820152601c60248201527f436f6d6d69746d656e7420616c7265616479207375626d6974746564000000006044820152606401610182565b6040805160608101825283815260208082018481524383850190815267ffffffffffffffff88165f8181528085528681203380835290865290879020955186559251600186015590516002909401939093558351868152918201859052927fc67cced54d126bd1721153300cdbf3ee48fdd6f98a5a643b5afa983f558419d5910160405180910390a3505050565b803567ffffffffffffffff8116811461032f575f5ffd5b919050565b80356001600160a01b038116811461032f575f5ffd5b5f5f6040838503121561035b575f5ffd5b61036483610318565b915061037260208401610334565b90509250929050565b5f5f83601f84011261038b575f5ffd5b50813567ffffffffffffffff8111156103a2575f5ffd5b6020830191508360208285010111156103b9575f5ffd5b9250929050565b5f5f83601f8401126103d0575f5ffd5b50813567ffffffffffffffff8111156103e7575f5ffd5b6020830191508360208260051b85010111156103b9575f5ffd5b5f5f5f5f5f5f5f5f5f5f60c08b8d03121561041a575f5ffd5b6104238b610318565b995061043160208c01610334565b985060408b013567ffffffffffffffff81111561044c575f5ffd5b6104588d828e0161037b565b90995097505060608b013567ffffffffffffffff811115610477575f5ffd5b6104838d828e016103c0565b90975095505060808b013567ffffffffffffffff8111156104a2575f5ffd5b6104ae8d828e0161037b565b90955093505060a08b013567ffffffffffffffff8111156104cd575f5ffd5b6104d98d828e016103c0565b915080935050809150509295989b9194979a5092959850565b5f5f5f60608486031215610504575f5ffd5b61050d84610318565b9560208501359550604090940135939250505056fea264697066735822122007845bd88c8b88030e3921286df1018709e141e2990396cc2f82dc6eece6d31f64736f6c634300081b0033",
}

// EigenKMSCommitmentRegistryABI is the input ABI used to generate the binding from.
// Deprecated: Use EigenKMSCommitmentRegistryMetaData.ABI instead.
var EigenKMSCommitmentRegistryABI = EigenKMSCommitmentRegistryMetaData.ABI

// EigenKMSCommitmentRegistryBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use EigenKMSCommitmentRegistryMetaData.Bin instead.
var EigenKMSCommitmentRegistryBin = EigenKMSCommitmentRegistryMetaData.Bin

// DeployEigenKMSCommitmentRegistry deploys a new Ethereum contract, binding an instance of EigenKMSCommitmentRegistry to it.
func DeployEigenKMSCommitmentRegistry(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *EigenKMSCommitmentRegistry, error) {
	parsed, err := EigenKMSCommitmentRegistryMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(EigenKMSCommitmentRegistryBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &EigenKMSCommitmentRegistry{EigenKMSCommitmentRegistryCaller: EigenKMSCommitmentRegistryCaller{contract: contract}, EigenKMSCommitmentRegistryTransactor: EigenKMSCommitmentRegistryTransactor{contract: contract}, EigenKMSCommitmentRegistryFilterer: EigenKMSCommitmentRegistryFilterer{contract: contract}}, nil
}

// EigenKMSCommitmentRegistry is an auto generated Go binding around an Ethereum contract.
type EigenKMSCommitmentRegistry struct {
	EigenKMSCommitmentRegistryCaller     // Read-only binding to the contract
	EigenKMSCommitmentRegistryTransactor // Write-only binding to the contract
	EigenKMSCommitmentRegistryFilterer   // Log filterer for contract events
}

// EigenKMSCommitmentRegistryCaller is an auto generated read-only Go binding around an Ethereum contract.
type EigenKMSCommitmentRegistryCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EigenKMSCommitmentRegistryTransactor is an auto generated write-only Go binding around an Ethereum contract.
type EigenKMSCommitmentRegistryTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EigenKMSCommitmentRegistryFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type EigenKMSCommitmentRegistryFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EigenKMSCommitmentRegistrySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type EigenKMSCommitmentRegistrySession struct {
	Contract     *EigenKMSCommitmentRegistry // Generic contract binding to set the session for
	CallOpts     bind.CallOpts               // Call options to use throughout this session
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// EigenKMSCommitmentRegistryCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type EigenKMSCommitmentRegistryCallerSession struct {
	Contract *EigenKMSCommitmentRegistryCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                     // Call options to use throughout this session
}

// EigenKMSCommitmentRegistryTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type EigenKMSCommitmentRegistryTransactorSession struct {
	Contract     *EigenKMSCommitmentRegistryTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                     // Transaction auth options to use throughout this session
}

// EigenKMSCommitmentRegistryRaw is an auto generated low-level Go binding around an Ethereum contract.
type EigenKMSCommitmentRegistryRaw struct {
	Contract *EigenKMSCommitmentRegistry // Generic contract binding to access the raw methods on
}

// EigenKMSCommitmentRegistryCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type EigenKMSCommitmentRegistryCallerRaw struct {
	Contract *EigenKMSCommitmentRegistryCaller // Generic read-only contract binding to access the raw methods on
}

// EigenKMSCommitmentRegistryTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type EigenKMSCommitmentRegistryTransactorRaw struct {
	Contract *EigenKMSCommitmentRegistryTransactor // Generic write-only contract binding to access the raw methods on
}

// NewEigenKMSCommitmentRegistry creates a new instance of EigenKMSCommitmentRegistry, bound to a specific deployed contract.
func NewEigenKMSCommitmentRegistry(address common.Address, backend bind.ContractBackend) (*EigenKMSCommitmentRegistry, error) {
	contract, err := bindEigenKMSCommitmentRegistry(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistry{EigenKMSCommitmentRegistryCaller: EigenKMSCommitmentRegistryCaller{contract: contract}, EigenKMSCommitmentRegistryTransactor: EigenKMSCommitmentRegistryTransactor{contract: contract}, EigenKMSCommitmentRegistryFilterer: EigenKMSCommitmentRegistryFilterer{contract: contract}}, nil
}

// NewEigenKMSCommitmentRegistryCaller creates a new read-only instance of EigenKMSCommitmentRegistry, bound to a specific deployed contract.
func NewEigenKMSCommitmentRegistryCaller(address common.Address, caller bind.ContractCaller) (*EigenKMSCommitmentRegistryCaller, error) {
	contract, err := bindEigenKMSCommitmentRegistry(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryCaller{contract: contract}, nil
}

// NewEigenKMSCommitmentRegistryTransactor creates a new write-only instance of EigenKMSCommitmentRegistry, bound to a specific deployed contract.
func NewEigenKMSCommitmentRegistryTransactor(address common.Address, transactor bind.ContractTransactor) (*EigenKMSCommitmentRegistryTransactor, error) {
	contract, err := bindEigenKMSCommitmentRegistry(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryTransactor{contract: contract}, nil
}

// NewEigenKMSCommitmentRegistryFilterer creates a new log filterer instance of EigenKMSCommitmentRegistry, bound to a specific deployed contract.
func NewEigenKMSCommitmentRegistryFilterer(address common.Address, filterer bind.ContractFilterer) (*EigenKMSCommitmentRegistryFilterer, error) {
	contract, err := bindEigenKMSCommitmentRegistry(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryFilterer{contract: contract}, nil
}

// bindEigenKMSCommitmentRegistry binds a generic wrapper to an already deployed contract.
func bindEigenKMSCommitmentRegistry(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := EigenKMSCommitmentRegistryMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _EigenKMSCommitmentRegistry.Contract.EigenKMSCommitmentRegistryCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.EigenKMSCommitmentRegistryTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.EigenKMSCommitmentRegistryTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _EigenKMSCommitmentRegistry.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.contract.Transact(opts, method, params...)
}

// Commitments is a free data retrieval call binding the contract method 0xfd935eb4.
//
// Solidity: function commitments(uint64 , address ) view returns(bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) Commitments(opts *bind.CallOpts, arg0 uint64, arg1 common.Address) (struct {
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	SubmittedAt    *big.Int
}, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "commitments", arg0, arg1)

	outstruct := new(struct {
		CommitmentHash [32]byte
		AckMerkleRoot  [32]byte
		SubmittedAt    *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.CommitmentHash = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.AckMerkleRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.SubmittedAt = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Commitments is a free data retrieval call binding the contract method 0xfd935eb4.
//
// Solidity: function commitments(uint64 , address ) view returns(bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) Commitments(arg0 uint64, arg1 common.Address) (struct {
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	SubmittedAt    *big.Int
}, error) {
	return _EigenKMSCommitmentRegistry.Contract.Commitments(&_EigenKMSCommitmentRegistry.CallOpts, arg0, arg1)
}

// Commitments is a free data retrieval call binding the contract method 0xfd935eb4.
//
// Solidity: function commitments(uint64 , address ) view returns(bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) Commitments(arg0 uint64, arg1 common.Address) (struct {
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	SubmittedAt    *big.Int
}, error) {
	return _EigenKMSCommitmentRegistry.Contract.Commitments(&_EigenKMSCommitmentRegistry.CallOpts, arg0, arg1)
}

// GetCommitment is a free data retrieval call binding the contract method 0x56a62d0f.
//
// Solidity: function getCommitment(uint64 epoch, address operator) view returns(bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) GetCommitment(opts *bind.CallOpts, epoch uint64, operator common.Address) (struct {
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	SubmittedAt    *big.Int
}, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "getCommitment", epoch, operator)

	outstruct := new(struct {
		CommitmentHash [32]byte
		AckMerkleRoot  [32]byte
		SubmittedAt    *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.CommitmentHash = *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)
	outstruct.AckMerkleRoot = *abi.ConvertType(out[1], new([32]byte)).(*[32]byte)
	outstruct.SubmittedAt = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// GetCommitment is a free data retrieval call binding the contract method 0x56a62d0f.
//
// Solidity: function getCommitment(uint64 epoch, address operator) view returns(bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) GetCommitment(epoch uint64, operator common.Address) (struct {
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	SubmittedAt    *big.Int
}, error) {
	return _EigenKMSCommitmentRegistry.Contract.GetCommitment(&_EigenKMSCommitmentRegistry.CallOpts, epoch, operator)
}

// GetCommitment is a free data retrieval call binding the contract method 0x56a62d0f.
//
// Solidity: function getCommitment(uint64 epoch, address operator) view returns(bytes32 commitmentHash, bytes32 ackMerkleRoot, uint256 submittedAt)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) GetCommitment(epoch uint64, operator common.Address) (struct {
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	SubmittedAt    *big.Int
}, error) {
	return _EigenKMSCommitmentRegistry.Contract.GetCommitment(&_EigenKMSCommitmentRegistry.CallOpts, epoch, operator)
}

// ProveEquivocation is a free data retrieval call binding the contract method 0x9fee311e.
//
// Solidity: function proveEquivocation(uint64 epoch, address dealer, bytes ack1, bytes32[] proof1, bytes ack2, bytes32[] proof2) pure returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) ProveEquivocation(opts *bind.CallOpts, epoch uint64, dealer common.Address, ack1 []byte, proof1 [][32]byte, ack2 []byte, proof2 [][32]byte) error {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "proveEquivocation", epoch, dealer, ack1, proof1, ack2, proof2)

	if err != nil {
		return err
	}

	return err

}

// ProveEquivocation is a free data retrieval call binding the contract method 0x9fee311e.
//
// Solidity: function proveEquivocation(uint64 epoch, address dealer, bytes ack1, bytes32[] proof1, bytes ack2, bytes32[] proof2) pure returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) ProveEquivocation(epoch uint64, dealer common.Address, ack1 []byte, proof1 [][32]byte, ack2 []byte, proof2 [][32]byte) error {
	return _EigenKMSCommitmentRegistry.Contract.ProveEquivocation(&_EigenKMSCommitmentRegistry.CallOpts, epoch, dealer, ack1, proof1, ack2, proof2)
}

// ProveEquivocation is a free data retrieval call binding the contract method 0x9fee311e.
//
// Solidity: function proveEquivocation(uint64 epoch, address dealer, bytes ack1, bytes32[] proof1, bytes ack2, bytes32[] proof2) pure returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) ProveEquivocation(epoch uint64, dealer common.Address, ack1 []byte, proof1 [][32]byte, ack2 []byte, proof2 [][32]byte) error {
	return _EigenKMSCommitmentRegistry.Contract.ProveEquivocation(&_EigenKMSCommitmentRegistry.CallOpts, epoch, dealer, ack1, proof1, ack2, proof2)
}

// SubmitCommitment is a paid mutator transaction binding the contract method 0xd50b3748.
//
// Solidity: function submitCommitment(uint64 epoch, bytes32 _commitmentHash, bytes32 _ackMerkleRoot) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactor) SubmitCommitment(opts *bind.TransactOpts, epoch uint64, _commitmentHash [32]byte, _ackMerkleRoot [32]byte) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.contract.Transact(opts, "submitCommitment", epoch, _commitmentHash, _ackMerkleRoot)
}

// SubmitCommitment is a paid mutator transaction binding the contract method 0xd50b3748.
//
// Solidity: function submitCommitment(uint64 epoch, bytes32 _commitmentHash, bytes32 _ackMerkleRoot) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) SubmitCommitment(epoch uint64, _commitmentHash [32]byte, _ackMerkleRoot [32]byte) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.SubmitCommitment(&_EigenKMSCommitmentRegistry.TransactOpts, epoch, _commitmentHash, _ackMerkleRoot)
}

// SubmitCommitment is a paid mutator transaction binding the contract method 0xd50b3748.
//
// Solidity: function submitCommitment(uint64 epoch, bytes32 _commitmentHash, bytes32 _ackMerkleRoot) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorSession) SubmitCommitment(epoch uint64, _commitmentHash [32]byte, _ackMerkleRoot [32]byte) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.SubmitCommitment(&_EigenKMSCommitmentRegistry.TransactOpts, epoch, _commitmentHash, _ackMerkleRoot)
}

// EigenKMSCommitmentRegistryCommitmentSubmittedIterator is returned from FilterCommitmentSubmitted and is used to iterate over the raw logs and unpacked data for CommitmentSubmitted events raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryCommitmentSubmittedIterator struct {
	Event *EigenKMSCommitmentRegistryCommitmentSubmitted // Event containing the contract specifics and raw log

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
func (it *EigenKMSCommitmentRegistryCommitmentSubmittedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EigenKMSCommitmentRegistryCommitmentSubmitted)
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
		it.Event = new(EigenKMSCommitmentRegistryCommitmentSubmitted)
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
func (it *EigenKMSCommitmentRegistryCommitmentSubmittedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EigenKMSCommitmentRegistryCommitmentSubmittedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EigenKMSCommitmentRegistryCommitmentSubmitted represents a CommitmentSubmitted event raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryCommitmentSubmitted struct {
	Epoch          uint64
	Operator       common.Address
	CommitmentHash [32]byte
	AckMerkleRoot  [32]byte
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterCommitmentSubmitted is a free log retrieval operation binding the contract event 0xc67cced54d126bd1721153300cdbf3ee48fdd6f98a5a643b5afa983f558419d5.
//
// Solidity: event CommitmentSubmitted(uint64 indexed epoch, address indexed operator, bytes32 commitmentHash, bytes32 ackMerkleRoot)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) FilterCommitmentSubmitted(opts *bind.FilterOpts, epoch []uint64, operator []common.Address) (*EigenKMSCommitmentRegistryCommitmentSubmittedIterator, error) {

	var epochRule []interface{}
	for _, epochItem := range epoch {
		epochRule = append(epochRule, epochItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.FilterLogs(opts, "CommitmentSubmitted", epochRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryCommitmentSubmittedIterator{contract: _EigenKMSCommitmentRegistry.contract, event: "CommitmentSubmitted", logs: logs, sub: sub}, nil
}

// WatchCommitmentSubmitted is a free log subscription operation binding the contract event 0xc67cced54d126bd1721153300cdbf3ee48fdd6f98a5a643b5afa983f558419d5.
//
// Solidity: event CommitmentSubmitted(uint64 indexed epoch, address indexed operator, bytes32 commitmentHash, bytes32 ackMerkleRoot)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) WatchCommitmentSubmitted(opts *bind.WatchOpts, sink chan<- *EigenKMSCommitmentRegistryCommitmentSubmitted, epoch []uint64, operator []common.Address) (event.Subscription, error) {

	var epochRule []interface{}
	for _, epochItem := range epoch {
		epochRule = append(epochRule, epochItem)
	}
	var operatorRule []interface{}
	for _, operatorItem := range operator {
		operatorRule = append(operatorRule, operatorItem)
	}

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.WatchLogs(opts, "CommitmentSubmitted", epochRule, operatorRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EigenKMSCommitmentRegistryCommitmentSubmitted)
				if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "CommitmentSubmitted", log); err != nil {
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

// ParseCommitmentSubmitted is a log parse operation binding the contract event 0xc67cced54d126bd1721153300cdbf3ee48fdd6f98a5a643b5afa983f558419d5.
//
// Solidity: event CommitmentSubmitted(uint64 indexed epoch, address indexed operator, bytes32 commitmentHash, bytes32 ackMerkleRoot)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) ParseCommitmentSubmitted(log types.Log) (*EigenKMSCommitmentRegistryCommitmentSubmitted, error) {
	event := new(EigenKMSCommitmentRegistryCommitmentSubmitted)
	if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "CommitmentSubmitted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
