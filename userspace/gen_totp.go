package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
)

func main() {
	key := make([]byte, 32) // 256-bit TOTP key
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	hexKey := hex.EncodeToString(key)

	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	base32Key := b32.EncodeToString(key)

	fmt.Println("TOTP Key (hex):   ", hexKey)
	fmt.Println("TOTP Key (base32):", base32Key)
}