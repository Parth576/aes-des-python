package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	"strconv"
	"unicode/utf8"
)
 
func reverse(s []string) []string {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }
    return s
}

func main() {
 
    // cipher key
    key := "thisis32bitlong.thisis32bitlong."
 
    // plaintext
	// b, err := ioutil.ReadFile("pt.txt")
	// CheckError(err)
	// pt := string(b)
	pt := "This is a secretThis is a secrey"
	
	
	splits := []string{}
	splits = SplitHeader(pt,16)
	blocks := len(splits)
	block := strconv.Itoa(blocks)
	fmt.Println("The number of blocks of 16 bytes are: " + block)


	fmt.Println("===========ENCODING IN ECB MODE===========")
	resultS,encres := encodeECBS([]byte(key), splits)
	fmt.Println(resultS)
	fmt.Println("")
	resultP := encodeECBP([]byte(key), splits)
	fmt.Println(resultP)
	fmt.Println("")

	fmt.Println("===========DECODING IN ECB MODE===========")
	resultS = decodeECBS([]byte(key), encres)
	fmt.Println(resultS)
	fmt.Println("")
	resultP = decodeECBP([]byte(key), encres)
	fmt.Println(resultP)
	fmt.Println("")

	// fmt.Println("===========ENCODING IN ECB MODE===========")
	// _,encres :=encodeECBS([]byte(key), splits)
	// encodeECBP([]byte(key), splits)

	// fmt.Println("===========DECODING IN ECB MODE===========")
	// decodeECBS([]byte(key), encres)
	// decodeECBP([]byte(key), encres)

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

func encodeECBS(key []byte, splits []string)  (string,[]string){
	
	results := []string{}
	start := time.Now()
	for index,element := range splits {
		fmt.Println("Block number " + strconv.Itoa(index))
		fmt.Println("Plaintext message in block: " + element)
		fmt.Println("Key : " + string(key))
		c := EncryptAES([]byte(key), element)
		fmt.Println("Encrypted Block :" + c)
		fmt.Println("")
		results = append(results, c)
	}
	time_taken := time.Since(start).String()
	fmt.Println("Time taken to encode serially: " + time_taken)
    // fmt.Println(results)
	// results = reverse(results)
	final_encrypted := ""
	for _,element := range results {
		final_encrypted += element
	}
	return final_encrypted,results
}

func encodeECBP(key []byte, splits []string) string {
	
	results := []string{}

	var wg sync.WaitGroup
	start := time.Now()
	for _,element := range splits {
		wg.Add(1)
		go func(element string) {
			defer wg.Done()
			c := EncryptAES([]byte(key), element)
			results = append(results, c)
		
		}(element)
	}
	wg.Wait()
	time_taken := time.Since(start).String()
	fmt.Println("Time taken to encode in parallel: " + time_taken)
	//wg.Wait()
    // fmt.Println(results)
	final_encrypted := ""
	for _,element := range results {
		final_encrypted += element
	}
	return final_encrypted
}

func decodeECBS(key []byte, enc_res []string)  string{
	
	results := []string{}
	start := time.Now()
	for index,element := range enc_res {
		fmt.Println("Block number " + strconv.Itoa(index))
		fmt.Println("Encrypted message in block: " + element)
		fmt.Println("Key : " + string(key))
		pt := DecryptAES([]byte(key), element)
		fmt.Println("Decrypted Block :" + pt)
		fmt.Println("")
		results = append(results, pt)
	}
	time_taken := time.Since(start).String()
	fmt.Println("Time taken to decode serially: " + time_taken)
    // fmt.Println(results)
	// results = reverse(results)
	final_plaintext := ""
	for _,element := range results {
		final_plaintext += element
	}
	return final_plaintext
}

func decodeECBP(key []byte, enc_res []string) string {
	
	results := []string{}

	var wg sync.WaitGroup
	start := time.Now()
	for _,element := range enc_res {
		wg.Add(1)
		go func(element string) {
			defer wg.Done()
			c := DecryptAES([]byte(key), element)
			results = append(results, c)
		
		}(element)
	}
	wg.Wait()
	time_taken := time.Since(start).String()
	fmt.Println("Time taken to decode in parallel: " + time_taken)
	//wg.Wait()
    // fmt.Println(results)
	results = reverse(results)
	final_encrypted := ""
	for _,element := range results {
		final_encrypted += element
	}
	return final_encrypted
}

func EncryptAES(key []byte, plaintext string) string {
	time.Sleep(1*time.Millisecond)
    c, err := aes.NewCipher(key)
    CheckError(err)
 
    out := make([]byte, len(plaintext))
    c.Encrypt(out, []byte(plaintext))
 
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