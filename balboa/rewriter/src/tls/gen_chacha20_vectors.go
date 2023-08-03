// You'll want to `go get golang.org/x/crypto/chacha20poly1305`

package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

func mustRand(buf []byte) {
	if _, err := rand.Read(buf); err != nil {
		log.Panic(err)
	}
}

func binEncode(b []byte) string {
	out := "&["
	for i, x := range b {
		if i != 0 {
			out += ","
		}
		out += fmt.Sprintf("%d", x)
	}
	out += "]"
	return out
}

func main() {
	N := 10
	fmt.Println("// Generated by gen_chacha20_vectors.go")
	fmt.Printf("static CHACHA20_TEST_VECTORS: [ChaChaTestVector; %d] = [\n", N)
	for i := 0; i < N; i++ {
		key := make([]byte, 32)
		mustRand(key)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			log.Panic(err)
		}
		plaintext := make([]byte, 48)
		mustRand(plaintext)
		nonce := make([]byte, aead.NonceSize())
		mustRand(nonce)
		ciphertext := aead.Seal(nil, nonce, plaintext, nil)
		tag := ciphertext[len(ciphertext)-aead.Overhead():]
		ciphertext = ciphertext[0 : len(ciphertext)-aead.Overhead()]
		fmt.Printf(
			"ChaChaTestVector {plaintext: %s, key: %s, nonce: %s, ciphertext: %s, tag: %s},\n",
			binEncode(plaintext),
			binEncode(key),
			binEncode(nonce),
			binEncode(ciphertext),
			binEncode(tag),
		)
	}
	fmt.Println("];")
}
