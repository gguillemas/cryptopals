package main

import (
	"./cryptopals"
	"bufio"
	"bytes"
	"fmt"
	"os"
)

func main() {
	fmt.Println("Set 1 - Challenge 1:")
	solveChallenge1()
	fmt.Println("Set 1 - Challenge 2:")
	solveChallenge2()
	fmt.Println("Set 1 - Challenge 3:")
	solveChallenge3()
	fmt.Println("Set 1 - Challenge 4:")
	solveChallenge4()
	fmt.Println("Set 1 - Challenge 5:")
	solveChallenge5()
	fmt.Println("Set 1 - Challenge 6:")
	solveChallenge6()
	fmt.Println("Set 1 - Challenge 7:")
	solveChallenge7()
	fmt.Println("Set 1 - Challenge 8:")
	solveChallenge8()
}

func solveChallenge1() {
	fmt.Printf("%s\n\n", cryptopals.Base64Encode(cryptopals.HexDecode(("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))))
}

func solveChallenge2() {
	fmt.Printf("%s\n\n", cryptopals.HexEncode(cryptopals.XorBytes([]byte("1c0111001f010100061a024b53535009181c"), []byte("686974207468652062756c6c277320657965"))))
}

func solveChallenge3() {
	plaintext, _ := cryptopals.XorCrack(cryptopals.HexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	fmt.Printf("%s\n\n", plaintext)
}

func solveChallenge4() {
	file, _ := os.Open("./files/4.txt")
	scanner := bufio.NewScanner(file)
	var candidate, plaintext []byte
	score := 0
	for scanner.Scan() {
		candidate, _ = cryptopals.XorCrack(cryptopals.HexDecode(scanner.Text()))
		if cryptopals.ScoreEnglish(candidate) > score {
			plaintext = candidate
			score = cryptopals.ScoreEnglish(candidate)
		}
	}
	fmt.Printf("%s\n", plaintext)
}

func solveChallenge5() {
	text, key := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE")
	keystream := bytes.Repeat(key, int(len(text)/len(key)+1))
	fmt.Printf("%s\n\n", cryptopals.HexEncode(cryptopals.XorBytes(text, keystream)))
}

func solveChallenge6() {
	file, _ := os.Open("./files/6.txt")
	scanner := bufio.NewScanner(file)
	contents := ""
	for scanner.Scan() {
		contents += scanner.Text()
	}
	ciphertext := cryptopals.Base64Decode(contents)
	distance, keylength, candidate := 0, len(ciphertext), len(ciphertext)
	for length := 1; length <= 40; length++ {
		distance1 := cryptopals.HammingDistance(ciphertext[0:length], ciphertext[length:length*2])
		distance2 := cryptopals.HammingDistance(ciphertext[length:length*2], ciphertext[length*2:length*3])
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
		_, keybyte := cryptopals.XorCrack(block)
		key = append(key, keybyte)
	}
	keystream := bytes.Repeat(key, int(len(ciphertext)/len(key)+1))
	fmt.Printf("%s\n", cryptopals.XorBytes(ciphertext, keystream))
}

func solveChallenge7() {
	file, _ := os.Open("./files/7.txt")
	scanner := bufio.NewScanner(file)
	contents := ""
	for scanner.Scan() {
		contents += scanner.Text()
	}
	ciphertext := cryptopals.Base64Decode(contents)
	key := []byte("YELLOW SUBMARINE")
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += 16 {
		plaintext = append(plaintext, cryptopals.AESDecryptBlock(ciphertext[i:i+16], key)...)
	}
	fmt.Printf("%s\n", plaintext)
}

func solveChallenge8() {
	file, _ := os.Open("./files/8.txt")
	scanner := bufio.NewScanner(file)
	var ciphertext, result []byte
	block := make([]byte, 16)
	hits, hits_result := 0, 0
	for scanner.Scan() {
		ciphertext = cryptopals.HexDecode(scanner.Text())
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
	fmt.Printf("%s\n\n", cryptopals.HexEncode(result))
}
