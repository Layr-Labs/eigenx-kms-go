package operator

import (
	"context"
	"fmt"

	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/clients/web3signer"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/config"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/contractCaller"
	"github.com/Layr-Labs/eigenx-kms-go/pkg/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"go.uber.org/zap"
)

type Operator struct {
	// TransactionPrivateKey is the private key for transaction signing (optional if using remote signer)
	TransactionPrivateKey string
	// TransactionAddress is the address for transaction signing when using remote signer
	TransactionAddress common.Address
	// UseRemoteSigner indicates whether a remote signer (Web3Signer) is being used for transactions
	UseRemoteSigner bool
	// SigningPrivateKey is the private key for cryptographic signing (BN254 or ECDSA)
	// For ECDSA with Web3Signer, this can be nil if ECDSAWeb3SignerClient is set
	SigningPrivateKey interface{}
	// SigningAddress is the address for ECDSA signing when using remote signer
	SigningAddress *common.Address
	// ECDSAWeb3SignerClient is the Web3Signer client for ECDSA key registration signing
	ECDSAWeb3SignerClient *web3signer.Client
	// ECDSASigningPublicKey is the hex-encoded public key for Web3Signer ECDSA signing
	ECDSASigningPublicKey string
	// Curve is the curve type for signing (BN254 or ECDSA)
	Curve          config.CurveType
	OperatorSetIds []uint32
}

func (o *Operator) DeriveAddress() (common.Address, error) {
	if o.UseRemoteSigner {
		if o.TransactionAddress == (common.Address{}) {
			return common.Address{}, fmt.Errorf("transaction address must be provided when using remote signer")
		}
		return o.TransactionAddress, nil
	}
	return util.DeriveAddressFromECDSAPrivateKeyString(o.TransactionPrivateKey)
}

type RegistrationConfig struct {
	AllocationDelay uint32
	MetadataUri     string
	Socket          string
}

func generateKeyData(operator *Operator, cc contractCaller.IContractCaller) ([]byte, error) {
	if operator.Curve == config.CurveTypeECDSA {
		// If a signing address is provided directly (e.g., when using Web3Signer), use it
		if operator.SigningAddress != nil {
			return operator.SigningAddress.Bytes(), nil
		}
		// Otherwise, derive from private key
		pk, ok := operator.SigningPrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing private key is not of type crypto-libs/ecdsa.PrivateKey and no signing address provided")
		}
		address, err := pk.DeriveAddress()
		if err != nil {
			return nil, fmt.Errorf("failed to derive address from ECDSA private key: %w", err)
		}
		return address.Bytes(), nil
	}
	if operator.Curve == config.CurveTypeBN254 {
		privateKey, ok := operator.SigningPrivateKey.(*bn254.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing private key is not of type *bn254.PrivateKeyConfig")
		}
		keyData, err := cc.EncodeBN254KeyData(privateKey.Public())
		if err != nil {
			return nil, fmt.Errorf("failed to encode BN254 key data:  %w", err)
		}
		return keyData, nil
	}
	return nil, fmt.Errorf("unsupported curve type: %s", operator.Curve)
}

func RegisterOperatorToOperatorSets(
	ctx context.Context,
	operatorContractCaller contractCaller.IContractCaller,
	avsAddress common.Address,
	operatorSetIds []uint32,
	operator *Operator,
	registrationConfig *RegistrationConfig,
	l *zap.Logger,
) (*types.Receipt, error) {
	operatorAddress, err := operator.DeriveAddress()
	if err != nil {
		l.Sugar().Fatalf("failed to derive operator address: %v", err)
		return nil, fmt.Errorf("failed to derive operator address: %w", err)
	}

	l.Sugar().Infow("Registering operator to AVS operator sets",
		zap.String("avsAddress", avsAddress.String()),
		zap.String("operatorAddress", operatorAddress.String()),
		zap.Uint32s("operatorSetIds", operatorSetIds),
		zap.String("curve", operator.Curve.String()),
	)
	keyData, err := generateKeyData(operator, operatorContractCaller)
	if err != nil {
		return nil, fmt.Errorf("failed to get key data: %w", err)
	}

	for _, operatorSetId := range operatorSetIds {
		setCurveType, err := operatorContractCaller.GetOperatorSetCurveType(avsAddress.String(), operatorSetId, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to get operator set curve type: %w", err)
		}
		l.Sugar().Infow("Operator set curve type",
			zap.String("avsAddress", avsAddress.String()),
			zap.Uint32("operatorSetId", operatorSetId),
			zap.String("curveType", setCurveType.String()),
		)
		if setCurveType != operator.Curve {
			return nil, fmt.Errorf("operator set curve type %s does not match operator curve type %s", setCurveType, operator.Curve)
		}

		var messageHash [32]byte
		var signature []byte

		switch operator.Curve {
		case config.CurveTypeECDSA:
			// Determine the signing address - either from SigningAddress or derived from private key
			var signingAddress common.Address
			if operator.SigningAddress != nil {
				signingAddress = *operator.SigningAddress
			} else if pk, ok := operator.SigningPrivateKey.(*ecdsa.PrivateKey); ok {
				var err error
				signingAddress, err = pk.DeriveAddress()
				if err != nil {
					return nil, fmt.Errorf("failed to derive address from ECDSA private key: %w", err)
				}
			} else {
				return nil, fmt.Errorf("ECDSA signing requires either SigningAddress or SigningPrivateKey")
			}

			messageHash, err = operatorContractCaller.GetOperatorECDSAKeyRegistrationMessageHash(ctx, operatorAddress, avsAddress, operatorSetId, signingAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to get operator registration message hash: %w", err)
			}

			// Sign using Web3Signer if configured, otherwise use local private key
			if operator.ECDSAWeb3SignerClient != nil {
				l.Sugar().Infow("Signing ECDSA key registration with Web3Signer",
					zap.String("publicKey", operator.ECDSASigningPublicKey),
					zap.String("signingAddress", signingAddress.String()),
				)

				sigHex, err := operator.ECDSAWeb3SignerClient.SignRaw(ctx, operator.ECDSASigningPublicKey, messageHash[:])
				if err != nil {
					return nil, fmt.Errorf("failed to sign message hash with Web3Signer: %w", err)
				}

				signature, err = hexutil.Decode(sigHex)
				if err != nil {
					return nil, fmt.Errorf("failed to decode Web3Signer signature: %w", err)
				}

				l.Sugar().Infow("Successfully signed with Web3Signer",
					zap.String("signature", sigHex),
				)
			} else {
				pk, ok := operator.SigningPrivateKey.(*ecdsa.PrivateKey)
				if !ok {
					return nil, fmt.Errorf("signing private key is not of type *ecdsa.PrivateKey and no Web3Signer configured")
				}

				rawSig, err := pk.Sign(messageHash[:])
				if err != nil {
					return nil, fmt.Errorf("failed to sign message hash: %w", err)
				}
				fmt.Printf("Sig: %+v\n", rawSig)

				signature, err = pk.SignAndPack(messageHash)
				if err != nil {
					return nil, fmt.Errorf("failed to sign message hash: %w", err)
				}
				fmt.Printf("Signature: %s\n", hexutil.Encode(signature))

				// verify the signature
				sig, err := ecdsa.NewSignatureFromBytes(signature)
				if err != nil {
					return nil, fmt.Errorf("failed to create signature from bytes: %w", err)
				}
				valid, err := sig.Verify(pk.Public(), messageHash)
				if err != nil {
					return nil, fmt.Errorf("failed to verify signature: %w", err)
				}
				if !valid {
					return nil, fmt.Errorf("signature verification failed")
				}
				l.Sugar().Infow("Signature verified successfully")
			}

		case config.CurveTypeBN254:
			messageHash, err = operatorContractCaller.GetOperatorBN254KeyRegistrationMessageHash(ctx, operatorAddress, avsAddress, operatorSetId, keyData)
			if err != nil {
				return nil, fmt.Errorf("failed to get operator registration message hash: %w", err)
			}
			pk, ok := operator.SigningPrivateKey.(*bn254.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("signing private key is not of type *bn254.PrivateKeyConfig")
			}
			sig, err := pk.SignSolidityCompatible(messageHash)
			if err != nil {
				return nil, err
			}
			g1Point := &bn254.G1Point{
				G1Affine: sig.GetG1Point(),
			}
			signature, err = g1Point.ToPrecompileFormat()
			if err != nil {
				return nil, fmt.Errorf("signature not in correct subgroup: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported curve type: %s", operator.Curve)
		}

		l.Sugar().Infow("Registering key for operator set",
			zap.String("avsAddress", avsAddress.String()),
			zap.Uint32("operatorSetId", operatorSetId),
			zap.String("operatorAddress", operatorAddress.String()),
			zap.String("curveType", operator.Curve.String()),
			zap.String("signature", hexutil.Encode(signature)),
			zap.String("keyData", hexutil.Encode(keyData)),
		)

		txReceipt, err := operatorContractCaller.RegisterKeyWithKeyRegistrar(
			ctx,
			operatorAddress,
			avsAddress,
			operatorSetId,
			signature,
			keyData,
		)
		if err != nil {
			l.Sugar().Fatalf("failed to register key with key registrar: %v", err)
			return nil, err
		}
		l.Sugar().Infow("Registered key with registrar",
			zap.String("avsAddress", avsAddress.String()),
			zap.Uint32("operatorSetId", operatorSetId),
			zap.String("operatorAddress", operatorAddress.String()),
			zap.String("transactionHash", txReceipt.TxHash.String()),
		)
	}

	return operatorContractCaller.CreateOperatorAndRegisterWithAvs(
		ctx,
		avsAddress,
		operatorAddress,
		operatorSetIds,
		registrationConfig.Socket,
		registrationConfig.AllocationDelay,
		registrationConfig.MetadataUri,
	)
}
