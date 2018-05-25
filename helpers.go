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

// RandomInt returns a random integer between min and max.
func RandomInt(min, max int) int {
	random := RandomBytes(1)
	return min + int(random[0])%(max-min)
}

// RandomBool returns true or false randomly.
func RandomBool() bool {
	random := RandomBytes(1)
	return int(random[0])%2 == 0
}

// RandomBytes returns a random byte slice of a specified length.
func RandomBytes(length int) []byte {
	random := make([]byte, length)
	rand.Read(random)
	return random
}

// AESECBEncrypt encrypts a byte slice with a key using the AES ECB mode.
func AESECBEncrypt(plaintext, key []byte) []byte {
	var ciphertext, block []byte
	for i := 0; i < len(plaintext); i += 16 {
		block = plaintext[i : i+16]
		ciphertext = append(ciphertext, MustAESEncryptBlock(block, key)...)
	}
	return ciphertext
}

// AESECBDecrypt decrypts a byte slice with a key using the AES ECB mode.
func AESECBDecrypt(ciphertext, key []byte) []byte {
	var plaintext, block []byte
	for i := 0; i < len(ciphertext); i += 16 {
		block = ciphertext[i : i+16]
		plaintext = append(plaintext, MustAESDecryptBlock(block, key)...)
	}
	return plaintext
}

// AESCBCEncrypt encrypts a byte slice with a key and IV using the AES CBC mode.
func AESCBCEncrypt(plaintext, key, iv []byte) []byte {
	var ciphertext, block []byte
	previousBlock := iv
	for i := 0; i < len(plaintext); i += 16 {
		block = plaintext[i : i+16]
		ciphertext = append(ciphertext, MustAESEncryptBlock(XORBytes(block, previousBlock), key)...)
		previousBlock = block
	}
	return ciphertext
}

// AESCBCDecrypt decrypts a byte slice with a key and IV using the AES CBC mode.
func AESCBCDecrypt(ciphertext, key, iv []byte) []byte {
	var plaintext, block []byte
	previousBlock := iv
	for i := 0; i < len(ciphertext); i += 16 {
		block = ciphertext[i : i+16]
		plaintext = append(plaintext, XORBytes(MustAESDecryptBlock(block, key), previousBlock)...)
		previousBlock = block
	}
	return plaintext
}

// PKCS7Pad pads a byte slice until a specified length following the PKCS7 standard.
func PKCS7Pad(text []byte, length int) []byte {
	return append(text, bytes.Repeat([]byte{byte(length - len(text))}, length-len(text))...)
}

// PKCS7Unpad removes the PKCS7 standard padding from a byte slice.
func PKCS7Unpad(text []byte) []byte {
	return text[:len(text)-int(text[len(text)-1])]
}

// AESEncryptBlock encrypts a byte slice corresponding with an AES block with a specified key.
func AESEncryptBlock(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	iv := bytes.Repeat([]byte{byte(0)}, aes.BlockSize)
	plaintext = plaintext[:aes.BlockSize]
	encrypter := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	encrypter.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// AESDecryptBlock decrypts a byte slice corresponding with an AES block with a specified key.
func AESDecryptBlock(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	iv := bytes.Repeat([]byte{byte(0)}, aes.BlockSize)
	ciphertext = ciphertext[:aes.BlockSize]
	decrypter := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// MustAESEncryptBlock encrypts a byte slice corresponding with an AES block with a specified key or panics.
func MustAESEncryptBlock(plaintext, key []byte) []byte {
	ciphertext, err := AESEncryptBlock(plaintext, key)
	if err != nil {
		panic(err)
	}

	return ciphertext
}

// MustAESDecryptBlock decrypts a byte slice corresponding with an AES block with a specified key or panics.
func MustAESDecryptBlock(ciphertext, key []byte) []byte {
	plaintext, err := AESDecryptBlock(ciphertext, key)
	if err != nil {
		panic(err)
	}

	return plaintext
}

// HammingDistance returns the edit distance between two byte slices.
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

// ScoreEnglish computes a score of the likelihood that a text is in English.
func ScoreEnglish(input []byte) int {
	english := []byte("ZJQXKVBPGWYFMCULDHRSNIOATEzjqxkvbpgwyfmculdhrsnioate ")
	score := 0
	for i, char := range english {
		score += (i + 1) * bytes.Count(input, []byte{byte(char)})
	}
	return score
}

// XORCrack attempts to recover the plaintext and key for a XOR encrypted ciphertext.
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

// XORBytes returns the result of performing the XOR operation over two byte slices.
func XORBytes(x, y []byte) []byte {
	z := make([]byte, len(x))
	for i := range x {
		z[i] = x[i] ^ y[i]
	}
	return z
}

// HexDecode returns the result of decoding an hexadecimal string into a byte slice.
func HexDecode(input string) ([]byte, error) {
	output, err := hex.DecodeString(input)
	if err != nil {
		return []byte{}, err
	}

	return output, nil
}

// MustHexDecode returns the result of decoding an hexadecimal string into a byte slice or panics.
func MustHexDecode(input string) []byte {
	output, err := HexDecode(input)
	if err != nil {
		panic(err)
	}

	return output
}

// HexEncode returns the result encoding a byte slice to a hexadecimal string.
func HexEncode(input []byte) string {
	output := make([]byte, hex.EncodedLen(len(input)))
	hex.Encode(output, input)
	return string(output)
}

// Base64Decode returns the result decoding a base64 string to a byte slice.
func Base64Decode(input string) ([]byte, error) {
	output, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return []byte{}, err
	}

	return output, nil
}

// MustBase64Decode returns the result decoding a base64 string to a byte slice or panics.
func MustBase64Decode(input string) []byte {
	output, err := Base64Decode(input)
	if err != nil {
		panic(err)
	}

	return output
}

// Base64Encode returns the result encoding a byte slice to a base64 string.
func Base64Encode(input []byte) string {
	output := make([]byte, base64.StdEncoding.EncodedLen(len(input)))
	base64.StdEncoding.Encode(output, input)
	return string(output)
}
