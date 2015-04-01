package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
)

func AESDecryptBlock(ciphertext, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{byte(0)}, aes.BlockSize)
	ciphertext = ciphertext[:aes.BlockSize]
	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext
}

func HammingDistance(x, y []byte) int {
	xor := XorBytes(x, y)
	var count, distance int
	for _, char := range xor {
		for count = 0; char != 0; count++ {
			char &= char - 1
		}
		distance += count
	}
	return distance
}

func ScoreEnglish(input []byte) int {
	english := []byte("ZJQXKVBPGWYFMCULDHRSNIOATEzjqxkvbpgwyfmculdhrsnioate ")
	score := 0
	for i, char := range english {
		score += (i + 1) * bytes.Count(input, []byte{byte(char)})
	}
	return score
}

func XorCrack(ciphertext []byte) ([]byte, byte) {
	length := len(ciphertext)
	var plaintext, candidate []byte
	var key byte
	for i := 0; i < 256; i++ {
		candidate = XorBytes(ciphertext, bytes.Repeat([]byte{byte(i)}, length))
		if ScoreEnglish(candidate) > ScoreEnglish(plaintext) {
			plaintext = candidate
			key = byte(i)
		}
	}
	return plaintext, key
}

func XorBytes(x, y []byte) []byte {
	z := make([]byte, len(x))
	for i := range x {
		z[i] = x[i] ^ y[i]
	}
	return z
}

func HexDecode(input string) []byte {
	output, _ := hex.DecodeString(input)
	return output
}

func HexEncode(input []byte) string {
	output := make([]byte, hex.EncodedLen(len(input)))
	hex.Encode(output, input)
	return string(output)
}

func Base64Decode(input string) []byte {
	output, _ := base64.StdEncoding.DecodeString(input)
	return output
}

func Base64Encode(input []byte) string {
	output := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(output, input)
	return string(output)
}
