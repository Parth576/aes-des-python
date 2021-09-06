package main

import (
	// "bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"
	"sync"
	"github.com/thanhpk/randstr"
)

func reverse(s []string) []string {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }
    return s
}


// (iv[], message) => xored string
func byteXOR(iv []byte, plaintext string) []byte {
	pt := []byte(plaintext)
	sliceL := len(pt)
	xored := make([]byte, sliceL)

	for i := 0; i<sliceL;i++ {
		xored[i] = pt[i] ^ iv[i]
	}
	return xored
}

func main() {
 
    // cipher key
	key := "thisis32bitlong.thisis32bitlong."
    iv := randstr.String(16)
	fmt.Println("The Initialization Vector is : " + iv)
	pt := "this is a secretthis is a secreythis is a secrer"

	fmt.Println("Plaintext is : " + pt)
	splits := []string{}
	splits = SplitHeader(pt,16)
	blocks := len(splits)
	block := strconv.Itoa(blocks)
	fmt.Println("The number of blocks of 16 bytes are: " + block)
	fmt.Println("")
	fmt.Println("===========ENCODING IN CBC MODE===========")
	encrypted,enc_res := encodeCBC([]byte(key), splits, []byte(iv))
	fmt.Println(encrypted)

	fmt.Println("===========DECODING IN CBC MODE===========")
	recovered_plaintext := decodeCBC([]byte(key), reverse(enc_res), []byte(iv))

	decodeCBCP([]byte(key), reverse(enc_res), []byte(iv))

	fmt.Println("Recovered plaintext is : " + recovered_plaintext)
}
 
func SplitHeader(longString string, maxlen int) []string {
    splits := []string{}

    var l, r int
    for l, r = 0, maxlen; r < len(longString); l, r = r, r+maxlen {
        for !utf8.RuneStart(longString[r]) {
            r--
        }
        splits = append(splits, longString[l:r])
    }
    splits = append(splits, longString[l:])
    return splits
}
//xor(iv+plaintext) => encrypt =>ciphertext => iv
func encodeCBC(key []byte, splits []string, iv []byte) (string, []string) {
	
	results := []string{}
	fmt.Println("Block 0.")
	fmt.Println("Iv/Ciphertext for xor: ")
	fmt.Println(iv)
	xored := byteXOR([]byte(iv), splits[0])
	fmt.Println("XOR'd plaintext block : ")
	fmt.Println(xored)
	ciphertext := EncryptAES([]byte(key), xored)
	fmt.Println("Encrypted block 0 : "  + ciphertext)
	fmt.Println("")
	results = append(results,ciphertext)

	for i:=1;i<len(splits);i++ {
		fmt.Println("Block " + strconv.Itoa(i) + ".")
		iv = []byte(ciphertext)
		fmt.Println("Iv/Ciphertext for xor: ")
		fmt.Println(iv)
		xored = byteXOR([]byte(iv), splits[i])
		fmt.Println("XOR'd plaintext block : ")
		fmt.Println(xored)
		ciphertext = EncryptAES([]byte(key),xored)
		fmt.Println("Encrypted block " + strconv.Itoa(i) + ": " + ciphertext)
		fmt.Println("")
		results = append(results, ciphertext)
	}
	final_encrypted := ""
	for _,element := range results {
		final_encrypted += element
	}
	return final_encrypted,results
}


func decodeCBC(key []byte, enc_res []string, iv []byte)  string {
	
	results := []string{}
	sliceL := len(enc_res) - 1
	start := time.Now()
	for i:=0;i<sliceL;i++ {
		fmt.Println("Block " + strconv.Itoa(i) + ".")
		decrypted := DecryptAES([]byte(key), enc_res[i])
		fmt.Println("Decrypted block value using key and ciphertext before XORing with previous ciphertext : " + decrypted)
		decryptXOR := byteXOR([]byte(enc_res[i+1]), decrypted)
		fmt.Println("Final plaintext after XORing decrytped with previous ciphertext : " + string(decryptXOR))
		results = append(results, string(decryptXOR))
		fmt.Println("")
	}
	fmt.Println("Block " + strconv.Itoa(sliceL) + ".")
	decrypted := DecryptAES([]byte(key), enc_res[sliceL])
	fmt.Println("Decrypted block value using key and ciphertext before XORing with previous ciphertext : " + decrypted)
	decryptXOR := byteXOR([]byte(iv), decrypted)
	fmt.Println("Final plaintext after XORing decrytped with previous ciphertext : " + string(decryptXOR))
	results = append(results, string(decryptXOR))
	fmt.Println("")
	time_taken := time.Since(start).String()
	fmt.Println("Time taken to decode serially: " + time_taken)
	results = reverse(results)
	final_plaintext := ""
	for _,element := range results {
		final_plaintext += element
	}
	return final_plaintext
}

func decodeCBCP(key []byte, enc_res []string, iv []byte)  string {
	
	results := []string{}
	sliceL := len(enc_res) - 1
	var wg sync.WaitGroup
	start := time.Now()
	for i:=0;i<sliceL;i++ {
		wg.Add(1)
		go func(key []byte, enc_res []string, i int) {
			defer wg.Done()
			decrypted := DecryptAES([]byte(key), enc_res[i])
			decryptXOR := byteXOR([]byte(enc_res[i+1]), decrypted)
			results = append(results, string(decryptXOR))
		}([]byte(key), enc_res, i)
	}
	wg.Wait()
	time_taken := time.Since(start).String()
	fmt.Println("Time taken to decode in parallel: " + time_taken)
	decrypted := DecryptAES([]byte(key), enc_res[sliceL])
	decryptXOR := byteXOR([]byte(iv), decrypted)
	results = append(results, string(decryptXOR))
	fmt.Println("")

	results = reverse(results)
	final_plaintext := ""
	for _,element := range results {
		final_plaintext += element
	}
	return final_plaintext
}

func EncryptAES(key []byte, plaintext []byte) string {

    c, err := aes.NewCipher(key)
    CheckError(err)
 
    out := make([]byte, len(plaintext))
    c.Encrypt(out, plaintext)
 
    return hex.EncodeToString(out)
}
 
func DecryptAES(key []byte, ct string) string{
	time.Sleep(1*time.Millisecond)
    ciphertext, _ := hex.DecodeString(ct)
 
    c, err := aes.NewCipher(key)
    CheckError(err)
 
    pt := make([]byte, len(ciphertext))
    c.Decrypt(pt, ciphertext)
 
    s := string(pt[:])
    return s
}
 
func CheckError(err error) {
    if err != nil {
        panic(err)
    }
}