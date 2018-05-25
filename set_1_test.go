package cryptopals

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"
)

func TestChallenge1(t *testing.T) {
	decoded := Base64Encode(HexDecode(("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))
	if decoded != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Fatal("decoded text does not match solution")
	}
}

func TestChallenge2(t *testing.T) {
	decoded := HexEncode(XORBytes(HexDecode("1c0111001f010100061a024b53535009181c"), HexDecode("686974207468652062756c6c277320657965")))
	if decoded != "746865206b696420646f6e277420706c6179" {
		t.Fatal("decoded text does not match solution")
	}
}

func TestChallenge3(t *testing.T) {
	plaintext, key := XORCrack(HexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	if key != byte(88) {
		t.Fatal("cracked key does not match solution")
	}
	if string(plaintext) != "Cooking MC's like a pound of bacon" {
		t.Fatal("cracked plaintext does not match solution")
	}
}

func TestChallenge4(t *testing.T) {
	file, err := os.Open(path.Join(resourcesPath, "input_4.txt"))
	if err != nil {
		log.Fatal(err)
	}

	score := 0
	var candidate, plaintext []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate, _ = XORCrack(HexDecode(scanner.Text()))
		if ScoreEnglish(candidate) > score {
			plaintext = candidate
			score = ScoreEnglish(candidate)
		}
	}

	if string(plaintext) != "Now that the party is jumping\n" {
		t.Fatal("cracked plaintext does not match solution")
	}
}

func TestChallenge5(t *testing.T) {
	text, key := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE")
	keystream := bytes.Repeat(key, int(len(text)/len(key)+1))
	ciphertext := HexEncode(XORBytes(text, keystream))

	if string(ciphertext) != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		t.Fatal("encrypted ciphertext does not match solution")
	}
}

func TestChallenge6(t *testing.T) {
	file, err := os.Open(path.Join(resourcesPath, "input_6.txt"))
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	contents := ""
	for scanner.Scan() {
		contents += scanner.Text()
	}

	ciphertext := Base64Decode(contents)
	distance, keylength, candidate := 0, len(ciphertext), len(ciphertext)
	for length := 1; length <= 40; length++ {
		distance1 := HammingDistance(ciphertext[0:length], ciphertext[length:length*2])
		distance2 := HammingDistance(ciphertext[length:length*2], ciphertext[length*2:length*3])
		distance = int((distance1 + distance2) / 2)
		if distance/length <= candidate {
			candidate = distance / length
			keylength = length
		}
	}

	transposition := make([][]byte, keylength)
	for i := 0; i < keylength; i++ {
		transposition[i] = make([]byte, int(len(ciphertext)/keylength)+1)
		for j := 0; j+i < len(ciphertext)-1; j += keylength {
			transposition[i][int(j/keylength)] = ciphertext[j+i]
		}
	}

	var key []byte
	for _, block := range transposition {
		_, keyByte := XORCrack(block)
		key = append(key, keyByte)
	}

	keystream := bytes.Repeat(key, int(len(ciphertext)/len(key)+1))

	solution, err := ioutil.ReadFile(path.Join(resourcesPath, "output_6.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(XORBytes(ciphertext, keystream), solution) != 0 {
		t.Fatal("cracked plaintext does not match solution")
	}
}

func TestChallenge7(t *testing.T) {
	file, err := os.Open(path.Join(resourcesPath, "input_7.txt"))
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(file)
	contents := ""
	for scanner.Scan() {
		contents += scanner.Text()
	}

	ciphertext := Base64Decode(contents)
	key := []byte("YELLOW SUBMARINE")

	var plaintext []byte
	for i := 0; i < len(ciphertext); i += 16 {
		plaintext = append(plaintext, AESDecryptBlock(ciphertext[i:i+16], key)...)
	}
	plaintext = PKCS7Unpad(plaintext)

	solution, err := ioutil.ReadFile(path.Join(resourcesPath, "output_7.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(plaintext, solution) != 0 {
		t.Fatal("decrypted plaintext does not match solution")
	}
}

func TestChallenge8(t *testing.T) {
	file, err := os.Open(path.Join(resourcesPath, "input_8.txt"))
	if err != nil {
		log.Fatal(err)
	}

	block := make([]byte, 16)
	hits, hits_result := 0, 0
	var ciphertext, result []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ciphertext = HexDecode(scanner.Text())
		for i := 0; i < len(ciphertext); i += 16 {
			block = ciphertext[i : i+16]
			hits = 0
			for j := 0; j < len(ciphertext); j += 16 {
				if bytes.Compare(block, ciphertext[j:j+16]) == 0 {
					hits++
					if hits > hits_result {
						result = ciphertext
						hits_result = hits
					}
				}
			}
		}
	}

	if HexEncode(result) != "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a" {
		t.Fatal("ciphertext does not match solution")
	}
}
