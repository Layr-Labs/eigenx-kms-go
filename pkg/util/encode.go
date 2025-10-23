package util

import "github.com/ethereum/go-ethereum/accounts/abi"

func EncodeString(str string) ([]byte, error) {
	// Define the ABI for a single string parameter
	stringType, _ := abi.NewType("string", "", nil)
	arguments := abi.Arguments{{Type: stringType}}

	// Encode the string
	encoded, err := arguments.Pack(str)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}
