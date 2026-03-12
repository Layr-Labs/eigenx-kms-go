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

// IEigenKMSCommitmentRegistryAckData is an auto generated low-level Go binding around an user-defined struct.
type IEigenKMSCommitmentRegistryAckData struct {
	Player         common.Address
	Dealer         common.Address
	ShareHash      [32]byte
	CommitmentHash [32]byte
	Proof          [][32]byte
}

// EigenKMSCommitmentRegistryMetaData contains all meta data concerning the EigenKMSCommitmentRegistry contract.
var EigenKMSCommitmentRegistryMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"avs\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"bn254CertificateVerifier\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"commitments\",\"inputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"ackMerkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"submittedAt\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"curveType\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"ecdsaCertificateVerifier\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"equivocationProven\",\"inputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getCommitment\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"operator\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"ackMerkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"submittedAt\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_avs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_operatorSetId\",\"type\":\"uint32\",\"internalType\":\"uint32\"},{\"name\":\"_ecdsaCertificateVerifier\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_bn254CertificateVerifier\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_curveType\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"operatorSetId\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"proveEquivocation\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"dealer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"ack1\",\"type\":\"tuple\",\"internalType\":\"structIEigenKMSCommitmentRegistry.AckData\",\"components\":[{\"name\":\"player\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"dealer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"shareHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}]},{\"name\":\"ack2\",\"type\":\"tuple\",\"internalType\":\"structIEigenKMSCommitmentRegistry.AckData\",\"components\":[{\"name\":\"player\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"dealer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"shareHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setCurveType\",\"inputs\":[{\"name\":\"_curveType\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"submitCommitment\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"internalType\":\"uint64\"},{\"name\":\"_commitmentHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"_ackMerkleRoot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"CommitmentSubmitted\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"indexed\":true,\"internalType\":\"uint64\"},{\"name\":\"operator\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"commitmentHash\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"ackMerkleRoot\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"CurveTypeUpdated\",\"inputs\":[{\"name\":\"oldCurveType\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"},{\"name\":\"newCurveType\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"EquivocationProven\",\"inputs\":[{\"name\":\"epoch\",\"type\":\"uint64\",\"indexed\":true,\"internalType\":\"uint64\"},{\"name\":\"dealer\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"player1\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"},{\"name\":\"player2\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"uint8\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"Ack1Invalid\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Ack2Invalid\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"AcksMustBeFromDifferentPlayers\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"BN254VerifierNotConfigured\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"CommitmentAlreadySubmitted\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"DealerMismatch\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ECDSAVerifierNotConfigured\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"EquivocationAlreadyProven\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidCommitmentHash\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidCurveType\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidMerkleRoot\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NoCommitment\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NoEquivocationDetected\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OperatorNotRegisteredBN254\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OperatorNotRegisteredECDSA\",\"inputs\":[]}]",
	Bin: "0x6080604052348015600e575f5ffd5b5060156019565b60d3565b5f54610100900460ff161560835760405162461bcd60e51b815260206004820152602760248201527f496e697469616c697a61626c653a20636f6e747261637420697320696e697469604482015266616c697a696e6760c81b606482015260840160405180910390fd5b5f5460ff9081161460d1575f805460ff191660ff9081179091556040519081527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15b565b610f36806100e05f395ff3fe608060405234801561000f575f5ffd5b50600436106100f0575f3560e01c8063b8c1430611610093578063e1ebfc3711610063578063e1ebfc371461027e578063ea1f0a7b146102aa578063f2fde38b146102bd578063fd935eb4146102d0575f5ffd5b8063b8c143061461021f578063d3728de414610232578063d50b374814610258578063de1164bb1461026b575f5ffd5b8063715018a6116100ce578063715018a6146101a25780637b1a1e26146101aa5780638da5cb5b146101e7578063ad0f95821461020c575f5ffd5b80630b3d2f92146100f45780630e1a71581461010957806356a62d0f1461011c575b5f5ffd5b610107610102366004610c36565b610309565b005b610107610117366004610c65565b6103aa565b61018261012a366004610cf6565b67ffffffffffffffff82165f9081526068602090815260408083206001600160a01b03851684528252918290208251606081018452815480825260018301549382018490526002909201549301839052919250925092565b604080519384526020840192909252908201526060015b60405180910390f35b61010761056b565b6101d76101b8366004610cf6565b606960209081525f928352604080842090915290825290205460ff1681565b6040519015158152602001610199565b6033546001600160a01b03165b6040516001600160a01b039091168152602001610199565b6066546101f4906001600160a01b031681565b6067546101f4906001600160a01b031681565b60675461024690600160a01b900460ff1681565b60405160ff9091168152602001610199565b610107610266366004610d27565b61057e565b6065546101f4906001600160a01b031681565b60655461029590600160a01b900463ffffffff1681565b60405163ffffffff9091168152602001610199565b6101076102b8366004610d6d565b61068a565b6101076102cb366004610df2565b610a1a565b6101826102de366004610cf6565b606860209081525f928352604080842090915290825290208054600182015460029092015490919083565b610311610a93565b8060ff1660011415801561032957508060ff16600214155b156103475760405163fdea7c0960e01b815260040160405180910390fd5b6067805460ff838116600160a01b81810260ff60a01b1985161790945560408051949093049091168084526020840191909152917fc2fda93842fa9624ded7e2dfc4d8012be02d28201944b8aa9dc0987fe4515678910160405180910390a15050565b5f54610100900460ff16158080156103c857505f54600160ff909116105b806103e15750303b1580156103e157505f5460ff166001145b6104495760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201526d191e481a5b9a5d1a585b1a5e995960921b60648201526084015b60405180910390fd5b5f805460ff19166001179055801561046a575f805461ff0019166101001790555b8160ff1660011415801561048257508160ff16600214155b156104a05760405163fdea7c0960e01b815260040160405180910390fd5b6104a8610aed565b6104b187610b1b565b606580546001600160a01b038881166001600160c01b031990921691909117600160a01b63ffffffff8916810291909117909255606680546001600160a01b031916878316179055606780549186166001600160a81b03199092169190911760ff85169092029190911790558015610562575f805461ff0019169055604051600181527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15b50505050505050565b610573610a93565b61057c5f610b1b565b565b8161059c5760405163029dd5dd60e41b815260040160405180910390fd5b806105ba57604051639dd854d360e01b815260040160405180910390fd5b67ffffffffffffffff83165f908152606860209081526040808320338452909152902054156105fb57604051626a17dd60e61b815260040160405180910390fd5b6040805160608101825283815260208082018481524383850190815267ffffffffffffffff88165f818152606885528681203380835290865290879020955186559251600186015590516002909401939093558351868152918201859052927fc67cced54d126bd1721153300cdbf3ee48fdd6f98a5a643b5afa983f558419d5910160405180910390a3505050565b67ffffffffffffffff84165f9081526068602090815260408083206001600160a01b0387168452909152902060010154806106d857604051635b07c98960e01b815260040160405180910390fd5b67ffffffffffffffff85165f9081526069602090815260408083206001600160a01b038816845290915290205460ff1615610726576040516301b5f1b760e71b815260040160405180910390fd5b6107336020830183610df2565b6001600160a01b03166107496020850185610df2565b6001600160a01b0316036107705760405163cb76bd6360e01b815260040160405180910390fd5b6107806040830160208401610df2565b6001600160a01b03166107996040850160208601610df2565b6001600160a01b0316146107c05760405163bcd365b360e01b815260040160405180910390fd5b816040013583604001351480156107de575081606001358360600135145b156107fc5760405163e609617560e01b815260040160405180910390fd5b5f61080a6020850185610df2565b61081a6040860160208701610df2565b8786604001358760600135604051602001610839959493929190610e0b565b60408051601f19818403018152919052805160209182012091505f9061086190850185610df2565b6108716040860160208701610df2565b8886604001358760600135604051602001610890959493929190610e0b565b60408051601f19818403018152919052805160209091012090506108f46108ba6080870187610e54565b808060200260200160405190810160405280939291908181526020018383602002808284375f92019190915250879250869150610b6c9050565b61091157604051637990605b60e01b815260040160405180910390fd5b61095b6109216080860186610e54565b808060200260200160405190810160405280939291908181526020018383602002808284375f92019190915250879250859150610b6c9050565b6109785760405163c00719db60e01b815260040160405180910390fd5b67ffffffffffffffff87165f8181526069602090815260408083206001600160a01b038b168085529083529220805460ff191660011790559091907f86c0a9d8ee45dd6550a34414591b4eddd9a5bdcdf34a78f4b6de6cfd5d185c73906109e190890189610df2565b6109ee6020890189610df2565b604080516001600160a01b0393841681529290911660208301520160405180910390a350505050505050565b610a22610a93565b6001600160a01b038116610a875760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b6064820152608401610440565b610a9081610b1b565b50565b6033546001600160a01b0316331461057c5760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e65726044820152606401610440565b5f54610100900460ff16610b135760405162461bcd60e51b815260040161044090610ea1565b61057c610b81565b603380546001600160a01b038381166001600160a01b0319831681179093556040519116919082907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0905f90a35050565b5f82610b788584610bb0565b14949350505050565b5f54610100900460ff16610ba75760405162461bcd60e51b815260040161044090610ea1565b61057c33610b1b565b5f81815b8451811015610bea57610be082868381518110610bd357610bd3610eec565b6020026020010151610bf2565b9150600101610bb4565b509392505050565b5f818310610c0c575f828152602084905260409020610c1a565b5f8381526020839052604090205b9392505050565b803560ff81168114610c31575f5ffd5b919050565b5f60208284031215610c46575f5ffd5b610c1a82610c21565b80356001600160a01b0381168114610c31575f5ffd5b5f5f5f5f5f5f60c08789031215610c7a575f5ffd5b610c8387610c4f565b9550610c9160208801610c4f565b9450604087013563ffffffff81168114610ca9575f5ffd5b9350610cb760608801610c4f565b9250610cc560808801610c4f565b9150610cd360a08801610c21565b90509295509295509295565b803567ffffffffffffffff81168114610c31575f5ffd5b5f5f60408385031215610d07575f5ffd5b610d1083610cdf565b9150610d1e60208401610c4f565b90509250929050565b5f5f5f60608486031215610d39575f5ffd5b610d4284610cdf565b95602085013595506040909401359392505050565b5f60a08284031215610d67575f5ffd5b50919050565b5f5f5f5f60808587031215610d80575f5ffd5b610d8985610cdf565b9350610d9760208601610c4f565b9250604085013567ffffffffffffffff811115610db2575f5ffd5b610dbe87828801610d57565b925050606085013567ffffffffffffffff811115610dda575f5ffd5b610de687828801610d57565b91505092959194509250565b5f60208284031215610e02575f5ffd5b610c1a82610c4f565b606095861b6bffffffffffffffffffffffff1990811682529490951b909316601485015260c09190911b6001600160c01b03191660288401526030830152605082015260700190565b5f5f8335601e19843603018112610e69575f5ffd5b83018035915067ffffffffffffffff821115610e83575f5ffd5b6020019150600581901b3603821315610e9a575f5ffd5b9250929050565b6020808252602b908201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960408201526a6e697469616c697a696e6760a81b606082015260800190565b634e487b7160e01b5f52603260045260245ffdfea26469706673582212204f301a5d7589a6305ef3c6813709b9aa1b771f6e2c63055e3b41eabc26c5c15764736f6c634300081b0033",
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

// Avs is a free data retrieval call binding the contract method 0xde1164bb.
//
// Solidity: function avs() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) Avs(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "avs")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Avs is a free data retrieval call binding the contract method 0xde1164bb.
//
// Solidity: function avs() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) Avs() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.Avs(&_EigenKMSCommitmentRegistry.CallOpts)
}

// Avs is a free data retrieval call binding the contract method 0xde1164bb.
//
// Solidity: function avs() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) Avs() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.Avs(&_EigenKMSCommitmentRegistry.CallOpts)
}

// Bn254CertificateVerifier is a free data retrieval call binding the contract method 0xb8c14306.
//
// Solidity: function bn254CertificateVerifier() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) Bn254CertificateVerifier(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "bn254CertificateVerifier")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Bn254CertificateVerifier is a free data retrieval call binding the contract method 0xb8c14306.
//
// Solidity: function bn254CertificateVerifier() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) Bn254CertificateVerifier() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.Bn254CertificateVerifier(&_EigenKMSCommitmentRegistry.CallOpts)
}

// Bn254CertificateVerifier is a free data retrieval call binding the contract method 0xb8c14306.
//
// Solidity: function bn254CertificateVerifier() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) Bn254CertificateVerifier() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.Bn254CertificateVerifier(&_EigenKMSCommitmentRegistry.CallOpts)
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

// CurveType is a free data retrieval call binding the contract method 0xd3728de4.
//
// Solidity: function curveType() view returns(uint8)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) CurveType(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "curveType")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// CurveType is a free data retrieval call binding the contract method 0xd3728de4.
//
// Solidity: function curveType() view returns(uint8)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) CurveType() (uint8, error) {
	return _EigenKMSCommitmentRegistry.Contract.CurveType(&_EigenKMSCommitmentRegistry.CallOpts)
}

// CurveType is a free data retrieval call binding the contract method 0xd3728de4.
//
// Solidity: function curveType() view returns(uint8)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) CurveType() (uint8, error) {
	return _EigenKMSCommitmentRegistry.Contract.CurveType(&_EigenKMSCommitmentRegistry.CallOpts)
}

// EcdsaCertificateVerifier is a free data retrieval call binding the contract method 0xad0f9582.
//
// Solidity: function ecdsaCertificateVerifier() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) EcdsaCertificateVerifier(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "ecdsaCertificateVerifier")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EcdsaCertificateVerifier is a free data retrieval call binding the contract method 0xad0f9582.
//
// Solidity: function ecdsaCertificateVerifier() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) EcdsaCertificateVerifier() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.EcdsaCertificateVerifier(&_EigenKMSCommitmentRegistry.CallOpts)
}

// EcdsaCertificateVerifier is a free data retrieval call binding the contract method 0xad0f9582.
//
// Solidity: function ecdsaCertificateVerifier() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) EcdsaCertificateVerifier() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.EcdsaCertificateVerifier(&_EigenKMSCommitmentRegistry.CallOpts)
}

// EquivocationProven is a free data retrieval call binding the contract method 0x7b1a1e26.
//
// Solidity: function equivocationProven(uint64 , address ) view returns(bool)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) EquivocationProven(opts *bind.CallOpts, arg0 uint64, arg1 common.Address) (bool, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "equivocationProven", arg0, arg1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// EquivocationProven is a free data retrieval call binding the contract method 0x7b1a1e26.
//
// Solidity: function equivocationProven(uint64 , address ) view returns(bool)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) EquivocationProven(arg0 uint64, arg1 common.Address) (bool, error) {
	return _EigenKMSCommitmentRegistry.Contract.EquivocationProven(&_EigenKMSCommitmentRegistry.CallOpts, arg0, arg1)
}

// EquivocationProven is a free data retrieval call binding the contract method 0x7b1a1e26.
//
// Solidity: function equivocationProven(uint64 , address ) view returns(bool)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) EquivocationProven(arg0 uint64, arg1 common.Address) (bool, error) {
	return _EigenKMSCommitmentRegistry.Contract.EquivocationProven(&_EigenKMSCommitmentRegistry.CallOpts, arg0, arg1)
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

// OperatorSetId is a free data retrieval call binding the contract method 0xe1ebfc37.
//
// Solidity: function operatorSetId() view returns(uint32)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) OperatorSetId(opts *bind.CallOpts) (uint32, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "operatorSetId")

	if err != nil {
		return *new(uint32), err
	}

	out0 := *abi.ConvertType(out[0], new(uint32)).(*uint32)

	return out0, err

}

// OperatorSetId is a free data retrieval call binding the contract method 0xe1ebfc37.
//
// Solidity: function operatorSetId() view returns(uint32)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) OperatorSetId() (uint32, error) {
	return _EigenKMSCommitmentRegistry.Contract.OperatorSetId(&_EigenKMSCommitmentRegistry.CallOpts)
}

// OperatorSetId is a free data retrieval call binding the contract method 0xe1ebfc37.
//
// Solidity: function operatorSetId() view returns(uint32)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) OperatorSetId() (uint32, error) {
	return _EigenKMSCommitmentRegistry.Contract.OperatorSetId(&_EigenKMSCommitmentRegistry.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _EigenKMSCommitmentRegistry.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) Owner() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.Owner(&_EigenKMSCommitmentRegistry.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryCallerSession) Owner() (common.Address, error) {
	return _EigenKMSCommitmentRegistry.Contract.Owner(&_EigenKMSCommitmentRegistry.CallOpts)
}

// Initialize is a paid mutator transaction binding the contract method 0x0e1a7158.
//
// Solidity: function initialize(address _owner, address _avs, uint32 _operatorSetId, address _ecdsaCertificateVerifier, address _bn254CertificateVerifier, uint8 _curveType) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactor) Initialize(opts *bind.TransactOpts, _owner common.Address, _avs common.Address, _operatorSetId uint32, _ecdsaCertificateVerifier common.Address, _bn254CertificateVerifier common.Address, _curveType uint8) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.contract.Transact(opts, "initialize", _owner, _avs, _operatorSetId, _ecdsaCertificateVerifier, _bn254CertificateVerifier, _curveType)
}

// Initialize is a paid mutator transaction binding the contract method 0x0e1a7158.
//
// Solidity: function initialize(address _owner, address _avs, uint32 _operatorSetId, address _ecdsaCertificateVerifier, address _bn254CertificateVerifier, uint8 _curveType) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) Initialize(_owner common.Address, _avs common.Address, _operatorSetId uint32, _ecdsaCertificateVerifier common.Address, _bn254CertificateVerifier common.Address, _curveType uint8) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.Initialize(&_EigenKMSCommitmentRegistry.TransactOpts, _owner, _avs, _operatorSetId, _ecdsaCertificateVerifier, _bn254CertificateVerifier, _curveType)
}

// Initialize is a paid mutator transaction binding the contract method 0x0e1a7158.
//
// Solidity: function initialize(address _owner, address _avs, uint32 _operatorSetId, address _ecdsaCertificateVerifier, address _bn254CertificateVerifier, uint8 _curveType) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorSession) Initialize(_owner common.Address, _avs common.Address, _operatorSetId uint32, _ecdsaCertificateVerifier common.Address, _bn254CertificateVerifier common.Address, _curveType uint8) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.Initialize(&_EigenKMSCommitmentRegistry.TransactOpts, _owner, _avs, _operatorSetId, _ecdsaCertificateVerifier, _bn254CertificateVerifier, _curveType)
}

// ProveEquivocation is a paid mutator transaction binding the contract method 0xea1f0a7b.
//
// Solidity: function proveEquivocation(uint64 epoch, address dealer, (address,address,bytes32,bytes32,bytes32[]) ack1, (address,address,bytes32,bytes32,bytes32[]) ack2) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactor) ProveEquivocation(opts *bind.TransactOpts, epoch uint64, dealer common.Address, ack1 IEigenKMSCommitmentRegistryAckData, ack2 IEigenKMSCommitmentRegistryAckData) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.contract.Transact(opts, "proveEquivocation", epoch, dealer, ack1, ack2)
}

// ProveEquivocation is a paid mutator transaction binding the contract method 0xea1f0a7b.
//
// Solidity: function proveEquivocation(uint64 epoch, address dealer, (address,address,bytes32,bytes32,bytes32[]) ack1, (address,address,bytes32,bytes32,bytes32[]) ack2) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) ProveEquivocation(epoch uint64, dealer common.Address, ack1 IEigenKMSCommitmentRegistryAckData, ack2 IEigenKMSCommitmentRegistryAckData) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.ProveEquivocation(&_EigenKMSCommitmentRegistry.TransactOpts, epoch, dealer, ack1, ack2)
}

// ProveEquivocation is a paid mutator transaction binding the contract method 0xea1f0a7b.
//
// Solidity: function proveEquivocation(uint64 epoch, address dealer, (address,address,bytes32,bytes32,bytes32[]) ack1, (address,address,bytes32,bytes32,bytes32[]) ack2) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorSession) ProveEquivocation(epoch uint64, dealer common.Address, ack1 IEigenKMSCommitmentRegistryAckData, ack2 IEigenKMSCommitmentRegistryAckData) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.ProveEquivocation(&_EigenKMSCommitmentRegistry.TransactOpts, epoch, dealer, ack1, ack2)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) RenounceOwnership() (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.RenounceOwnership(&_EigenKMSCommitmentRegistry.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.RenounceOwnership(&_EigenKMSCommitmentRegistry.TransactOpts)
}

// SetCurveType is a paid mutator transaction binding the contract method 0x0b3d2f92.
//
// Solidity: function setCurveType(uint8 _curveType) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactor) SetCurveType(opts *bind.TransactOpts, _curveType uint8) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.contract.Transact(opts, "setCurveType", _curveType)
}

// SetCurveType is a paid mutator transaction binding the contract method 0x0b3d2f92.
//
// Solidity: function setCurveType(uint8 _curveType) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) SetCurveType(_curveType uint8) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.SetCurveType(&_EigenKMSCommitmentRegistry.TransactOpts, _curveType)
}

// SetCurveType is a paid mutator transaction binding the contract method 0x0b3d2f92.
//
// Solidity: function setCurveType(uint8 _curveType) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorSession) SetCurveType(_curveType uint8) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.SetCurveType(&_EigenKMSCommitmentRegistry.TransactOpts, _curveType)
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

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistrySession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.TransferOwnership(&_EigenKMSCommitmentRegistry.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _EigenKMSCommitmentRegistry.Contract.TransferOwnership(&_EigenKMSCommitmentRegistry.TransactOpts, newOwner)
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

// EigenKMSCommitmentRegistryCurveTypeUpdatedIterator is returned from FilterCurveTypeUpdated and is used to iterate over the raw logs and unpacked data for CurveTypeUpdated events raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryCurveTypeUpdatedIterator struct {
	Event *EigenKMSCommitmentRegistryCurveTypeUpdated // Event containing the contract specifics and raw log

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
func (it *EigenKMSCommitmentRegistryCurveTypeUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EigenKMSCommitmentRegistryCurveTypeUpdated)
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
		it.Event = new(EigenKMSCommitmentRegistryCurveTypeUpdated)
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
func (it *EigenKMSCommitmentRegistryCurveTypeUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EigenKMSCommitmentRegistryCurveTypeUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EigenKMSCommitmentRegistryCurveTypeUpdated represents a CurveTypeUpdated event raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryCurveTypeUpdated struct {
	OldCurveType uint8
	NewCurveType uint8
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterCurveTypeUpdated is a free log retrieval operation binding the contract event 0xc2fda93842fa9624ded7e2dfc4d8012be02d28201944b8aa9dc0987fe4515678.
//
// Solidity: event CurveTypeUpdated(uint8 oldCurveType, uint8 newCurveType)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) FilterCurveTypeUpdated(opts *bind.FilterOpts) (*EigenKMSCommitmentRegistryCurveTypeUpdatedIterator, error) {

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.FilterLogs(opts, "CurveTypeUpdated")
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryCurveTypeUpdatedIterator{contract: _EigenKMSCommitmentRegistry.contract, event: "CurveTypeUpdated", logs: logs, sub: sub}, nil
}

// WatchCurveTypeUpdated is a free log subscription operation binding the contract event 0xc2fda93842fa9624ded7e2dfc4d8012be02d28201944b8aa9dc0987fe4515678.
//
// Solidity: event CurveTypeUpdated(uint8 oldCurveType, uint8 newCurveType)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) WatchCurveTypeUpdated(opts *bind.WatchOpts, sink chan<- *EigenKMSCommitmentRegistryCurveTypeUpdated) (event.Subscription, error) {

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.WatchLogs(opts, "CurveTypeUpdated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EigenKMSCommitmentRegistryCurveTypeUpdated)
				if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "CurveTypeUpdated", log); err != nil {
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

// ParseCurveTypeUpdated is a log parse operation binding the contract event 0xc2fda93842fa9624ded7e2dfc4d8012be02d28201944b8aa9dc0987fe4515678.
//
// Solidity: event CurveTypeUpdated(uint8 oldCurveType, uint8 newCurveType)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) ParseCurveTypeUpdated(log types.Log) (*EigenKMSCommitmentRegistryCurveTypeUpdated, error) {
	event := new(EigenKMSCommitmentRegistryCurveTypeUpdated)
	if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "CurveTypeUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// EigenKMSCommitmentRegistryEquivocationProvenIterator is returned from FilterEquivocationProven and is used to iterate over the raw logs and unpacked data for EquivocationProven events raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryEquivocationProvenIterator struct {
	Event *EigenKMSCommitmentRegistryEquivocationProven // Event containing the contract specifics and raw log

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
func (it *EigenKMSCommitmentRegistryEquivocationProvenIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EigenKMSCommitmentRegistryEquivocationProven)
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
		it.Event = new(EigenKMSCommitmentRegistryEquivocationProven)
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
func (it *EigenKMSCommitmentRegistryEquivocationProvenIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EigenKMSCommitmentRegistryEquivocationProvenIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EigenKMSCommitmentRegistryEquivocationProven represents a EquivocationProven event raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryEquivocationProven struct {
	Epoch   uint64
	Dealer  common.Address
	Player1 common.Address
	Player2 common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterEquivocationProven is a free log retrieval operation binding the contract event 0x86c0a9d8ee45dd6550a34414591b4eddd9a5bdcdf34a78f4b6de6cfd5d185c73.
//
// Solidity: event EquivocationProven(uint64 indexed epoch, address indexed dealer, address player1, address player2)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) FilterEquivocationProven(opts *bind.FilterOpts, epoch []uint64, dealer []common.Address) (*EigenKMSCommitmentRegistryEquivocationProvenIterator, error) {

	var epochRule []interface{}
	for _, epochItem := range epoch {
		epochRule = append(epochRule, epochItem)
	}
	var dealerRule []interface{}
	for _, dealerItem := range dealer {
		dealerRule = append(dealerRule, dealerItem)
	}

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.FilterLogs(opts, "EquivocationProven", epochRule, dealerRule)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryEquivocationProvenIterator{contract: _EigenKMSCommitmentRegistry.contract, event: "EquivocationProven", logs: logs, sub: sub}, nil
}

// WatchEquivocationProven is a free log subscription operation binding the contract event 0x86c0a9d8ee45dd6550a34414591b4eddd9a5bdcdf34a78f4b6de6cfd5d185c73.
//
// Solidity: event EquivocationProven(uint64 indexed epoch, address indexed dealer, address player1, address player2)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) WatchEquivocationProven(opts *bind.WatchOpts, sink chan<- *EigenKMSCommitmentRegistryEquivocationProven, epoch []uint64, dealer []common.Address) (event.Subscription, error) {

	var epochRule []interface{}
	for _, epochItem := range epoch {
		epochRule = append(epochRule, epochItem)
	}
	var dealerRule []interface{}
	for _, dealerItem := range dealer {
		dealerRule = append(dealerRule, dealerItem)
	}

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.WatchLogs(opts, "EquivocationProven", epochRule, dealerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EigenKMSCommitmentRegistryEquivocationProven)
				if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "EquivocationProven", log); err != nil {
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

// ParseEquivocationProven is a log parse operation binding the contract event 0x86c0a9d8ee45dd6550a34414591b4eddd9a5bdcdf34a78f4b6de6cfd5d185c73.
//
// Solidity: event EquivocationProven(uint64 indexed epoch, address indexed dealer, address player1, address player2)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) ParseEquivocationProven(log types.Log) (*EigenKMSCommitmentRegistryEquivocationProven, error) {
	event := new(EigenKMSCommitmentRegistryEquivocationProven)
	if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "EquivocationProven", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// EigenKMSCommitmentRegistryInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryInitializedIterator struct {
	Event *EigenKMSCommitmentRegistryInitialized // Event containing the contract specifics and raw log

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
func (it *EigenKMSCommitmentRegistryInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EigenKMSCommitmentRegistryInitialized)
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
		it.Event = new(EigenKMSCommitmentRegistryInitialized)
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
func (it *EigenKMSCommitmentRegistryInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EigenKMSCommitmentRegistryInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EigenKMSCommitmentRegistryInitialized represents a Initialized event raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryInitialized struct {
	Version uint8
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) FilterInitialized(opts *bind.FilterOpts) (*EigenKMSCommitmentRegistryInitializedIterator, error) {

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryInitializedIterator{contract: _EigenKMSCommitmentRegistry.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *EigenKMSCommitmentRegistryInitialized) (event.Subscription, error) {

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EigenKMSCommitmentRegistryInitialized)
				if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "Initialized", log); err != nil {
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

// ParseInitialized is a log parse operation binding the contract event 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.
//
// Solidity: event Initialized(uint8 version)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) ParseInitialized(log types.Log) (*EigenKMSCommitmentRegistryInitialized, error) {
	event := new(EigenKMSCommitmentRegistryInitialized)
	if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// EigenKMSCommitmentRegistryOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryOwnershipTransferredIterator struct {
	Event *EigenKMSCommitmentRegistryOwnershipTransferred // Event containing the contract specifics and raw log

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
func (it *EigenKMSCommitmentRegistryOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(EigenKMSCommitmentRegistryOwnershipTransferred)
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
		it.Event = new(EigenKMSCommitmentRegistryOwnershipTransferred)
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
func (it *EigenKMSCommitmentRegistryOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *EigenKMSCommitmentRegistryOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// EigenKMSCommitmentRegistryOwnershipTransferred represents a OwnershipTransferred event raised by the EigenKMSCommitmentRegistry contract.
type EigenKMSCommitmentRegistryOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*EigenKMSCommitmentRegistryOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &EigenKMSCommitmentRegistryOwnershipTransferredIterator{contract: _EigenKMSCommitmentRegistry.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *EigenKMSCommitmentRegistryOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _EigenKMSCommitmentRegistry.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(EigenKMSCommitmentRegistryOwnershipTransferred)
				if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
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

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_EigenKMSCommitmentRegistry *EigenKMSCommitmentRegistryFilterer) ParseOwnershipTransferred(log types.Log) (*EigenKMSCommitmentRegistryOwnershipTransferred, error) {
	event := new(EigenKMSCommitmentRegistryOwnershipTransferred)
	if err := _EigenKMSCommitmentRegistry.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
