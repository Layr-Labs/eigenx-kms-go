package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Your public key in both formats
	withPrefix := "04b6b4d44a178b5a33e5dbb3e60fc415f14e81555e47f7a73d0945a34f81bdeda71deee7f71e20944d3fbf7e15b5b3487fbaa68f479d14694ff3333a1bdf239533"
	withoutPrefix := "b6b4d44a178b5a33e5dbb3e60fc415f14e81555e47f7a73d0945a34f81bdeda71deee7f71e20944d3fbf7e15b5b3487fbaa68f479d14694ff3333a1bdf239533"

	// Decode hex strings
	pubKeyWithPrefix, _ := hex.DecodeString(withPrefix)
	pubKeyWithoutPrefix, _ := hex.DecodeString(withoutPrefix)

	// Method 1: Using the standard format (with 0x04 prefix)
	pubKey1, err := crypto.UnmarshalPubkey(pubKeyWithPrefix)
	if err != nil {
		panic(err)
	}
	address1 := crypto.PubkeyToAddress(*pubKey1)

	// Method 2: Adding 0x04 prefix to the unprefixed version
	pubKeyWithAddedPrefix := append([]byte{0x04}, pubKeyWithoutPrefix...)
	pubKey2, err := crypto.UnmarshalPubkey(pubKeyWithAddedPrefix)
	if err != nil {
		panic(err)
	}
	address2 := crypto.PubkeyToAddress(*pubKey2)

	fmt.Println("Address from public key WITH 0x04 prefix:   ", address1.Hex())
	fmt.Println("Address from public key WITHOUT prefix (added):", address2.Hex())
	fmt.Println("Addresses match:", address1 == address2)
}
