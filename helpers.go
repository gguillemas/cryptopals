package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

const resourcesPath string = "_resources"

func RandomInt(min, max int) int {
	random := RandomBytes(1)
	return min + int(random[0])%(max-min)
}

func RandomBool() bool {
	random := RandomBytes(1)
	return int(random[0])%2 == 0
}

func RandomBytes(length int) []byte {
	random := make([]byte, length)
	rand.Read(random)
	return random
}

func AESECBEncrypt(plaintext, key []byte) []byte {
	var ciphertext, block []byte
	for i := 0; i < len(plaintext); i += 16 {
		block = plaintext[i : i+16]
		ciphertext = append(ciphertext, AESEncryptBlock(block, key)...)
	}
	return ciphertext
}

func AESECBDecrypt(ciphertext, key []byte) []byte {
	var plaintext, block []byte
	for i := 0; i < len(ciphertext); i += 16 {
		block = ciphertext[i : i+16]
		plaintext = append(plaintext, AESDecryptBlock(block, key)...)
	}
	return plaintext
}

func AESCBCEncrypt(plaintext, key, iv []byte) []byte {
	var ciphertext, block []byte
	previousBlock := iv
	for i := 0; i < len(plaintext); i += 16 {
		block = plaintext[i : i+16]
		ciphertext = append(ciphertext, AESEncryptBlock(XORBytes(block, previousBlock), key)...)
		previousBlock = block
	}
	return ciphertext
}

func AESCBCDecrypt(ciphertext, key, iv []byte) []byte {
	var plaintext, block []byte
	previousBlock := iv
	for i := 0; i < len(ciphertext); i += 16 {
		block = ciphertext[i : i+16]
		plaintext = append(plaintext, XORBytes(AESDecryptBlock(block, key), previousBlock)...)
		previousBlock = block
	}
	return plaintext
}

func PKCS7Pad(text []byte, length int) []byte {
	return append(text, bytes.Repeat([]byte{byte(length - len(text))}, length-len(text))...)
}

func PKCS7Unpad(text []byte) []byte {
	return text[:len(text)-int(text[len(text)-1])]
}

func AESEncryptBlock(ciphertext, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := bytes.Repeat([]byte{byte(0)}, aes.BlockSize)
	ciphertext = ciphertext[:aes.BlockSize]
	decrypter := cipher.NewCBCEncrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext
}

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
	xor := XORBytes(x, y)
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

func XORCrack(ciphertext []byte) ([]byte, byte) {
	length := len(ciphertext)
	var plaintext, candidate []byte
	var key byte
	for i := 0; i < 256; i++ {
		candidate = XORBytes(ciphertext, bytes.Repeat([]byte{byte(i)}, length))
		if ScoreEnglish(candidate) > ScoreEnglish(plaintext) {
			plaintext = candidate
			key = byte(i)
		}
	}
	return plaintext, key
}

func XORBytes(x, y []byte) []byte {
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
