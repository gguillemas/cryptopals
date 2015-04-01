package main

import (
	"./cryptopals"
	"bufio"
	"bytes"
	"fmt"
	"os"
)

func main() {
	fmt.Println("Set 2 - Challenge 9:")
	solveChallenge9()
	fmt.Println("Set 2 - Challenge 10:")
	solveChallenge10()
	fmt.Println("Set 2 - Challenge 11:")
	solveChallenge11()
	fmt.Println("Set 2 - Challenge 12:")
	solveChallenge12()
	fmt.Println("Set 2 - Challenge 13:")
	solveChallenge13()
	fmt.Println("Set 2 - Challenge 14:")
	solveChallenge14()
	fmt.Println("Set 2 - Challenge 15:")
	solveChallenge15()
	fmt.Println("Set 2 - Challenge 16:")
	solveChallenge16()
}

func solveChallenge9() {
	fmt.Printf("%s\n\n", cryptopals.PKCS7Pad([]byte("YELLOW SUBMARINE"), 20))
}

func solveChallenge10() {
	file, _ := os.Open("./files/10.txt")
  scanner := bufio.NewScanner(file)
  contents := ""
  for scanner.Scan() {
    contents += scanner.Text()
  }
	ciphertext := cryptopals.Base64Decode(contents)
	fmt.Printf("%s\n", cryptopals.AESCBCDecrypt(ciphertext, []byte("YELLOW SUBMARINE"), bytes.Repeat([]byte{byte(0)}, 16)))
}

func solveChallenge11() {
	key := cryptopals.RandomBytes(16)
	data := cryptopals.RandomBytes(128)
	iv := make([]byte, 16)
	for i := 0; i < 20; i++ {
		head := bytes.Repeat([]byte{byte(0)}, cryptopals.RandomInt(5, 10))
		tail := bytes.Repeat([]byte{byte(0)}, cryptopals.RandomInt(5, 10))
		plaintext := append(head, data...)
		plaintext = append(plaintext, tail...)
		ciphertext := make([]byte, len(plaintext))
		if cryptopals.RandomBool() {
			ciphertext = cryptopals.AESCBCEncrypt(plaintext, key, iv)
		} else {
			ciphertext = cryptopals.AESECBEncrypt(plaintext, key)
		}
		if bytes.Compare(ciphertext[32:48], cryptopals.AESEncryptBlock(plaintext[32:48], key)) == 0 {
			fmt.Println("Encrypted with ECB.")
		} else {
			fmt.Println("Encrypted with CBC.")
		}
	}
}

func solveChallenge12() {
	key := cryptopals.RandomBytes(16)
	known := cryptopals.Base64Decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	unknown := RandomBytes(128)
	ciphertext := AESECBEncrypt(append(known, unknown...), key)
}

func solveChallenge13() {
}

func solveChallenge14() {
}

func solveChallenge15() {
}

func solveChallenge16() {
}
