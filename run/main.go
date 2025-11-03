package main

import (
	"fmt"

	"github.com/dwdwow/evmutil-go"
)

func main() {
	// encrypted, address, err := evmutil.GenerateAndEncryptNewKey()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Encrypted:", encrypted)
	// fmt.Println("Address:", address)

	_, address, err := evmutil.ReadEncryptedPrivateKeyFromTerminal()
	if err != nil {
		panic(err)
	}
	fmt.Println("Address:", address)

	// privateKeyHex, err := evmutil.PrivateKeyHexFromWallet(wallet)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Private key hex:", privateKeyHex)
}
