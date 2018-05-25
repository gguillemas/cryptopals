package cryptopals

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestChallenge9(t *testing.T) {
	padded := PKCS7Pad([]byte("YELLOW SUBMARINE"), 20)
	if bytes.Compare(padded, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")) != 0 {
		t.Fatal("padded text does not match solution")
	}
}

func TestChallenge10(t *testing.T) {
	inputFile, err := os.Open(path.Join(resourcesPath, "input_10.txt"))
	if err != nil {
		t.Fatal(err)
	}

	contents := ""
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		contents += scanner.Text()
	}

	ciphertext := MustBase64Decode(contents)
	plaintext := AESCBCDecrypt(ciphertext, []byte("YELLOW SUBMARINE"), bytes.Repeat([]byte{byte(0)}, 16))
	plaintext = PKCS7Unpad(plaintext)

	output, err := ioutil.ReadFile(path.Join(resourcesPath, "output_10.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(plaintext, output) != 0 {
		t.Fatal("decrypted plaintext does not match solution")
	}
}

func TestChallenge11(t *testing.T) {
	key := RandomBytes(16)
	data := RandomBytes(128)
	iv := make([]byte, 16)

	var cbc bool
	for i := 0; i < 20; i++ {
		head := bytes.Repeat([]byte{byte(0)}, RandomInt(5, 10))
		tail := bytes.Repeat([]byte{byte(0)}, RandomInt(5, 10))

		plaintext := append(head, data...)
		plaintext = append(plaintext, tail...)

		ciphertext := make([]byte, len(plaintext))

		if RandomBool() {
			cbc = true
			ciphertext = AESCBCEncrypt(plaintext, key, iv)
		} else {
			cbc = false
			ciphertext = AESECBEncrypt(plaintext, key)
		}

		if bytes.Compare(ciphertext[32:48], MustAESEncryptBlock(plaintext[32:48], key)) == 0 {
			if cbc {
				t.Fatal("ciphertext incorrectly identified as AES ECB")
			}
		} else {
			if !cbc {
				t.Fatal("ciphertext incorrectly identified as AES CBC")
			}
		}
	}
}
