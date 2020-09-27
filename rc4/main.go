package main

import (
	"os/exec"
	"time"
    "crypto/rc4"
    "fmt"
    "log"
    "math/rand"
)

func doEncryption(iv []byte, randPreKey []byte, pltext []byte) ([]byte, []byte) {
	fullKey := make([]byte, 16)
	for i := 0; i < 16; i += 1 {
		if i < 3 {
			fullKey[i] = iv[i]
		} else {
			fullKey[i] = randPreKey[i-3]
		}
	}
	c, err := rc4.NewCipher(fullKey)
	if err != nil {
		log.Fatal(err)
	}
	cipher := make([]byte, len(pltext))
	c.XORKeyStream(cipher, pltext)
	return cipher, fullKey
}

func getM0(iv []byte, randPreKey []byte, pltext []byte) (byte, int) {
	var most_m0 = make(map[byte]int, 256)
	for i := 0; i < 256; i++ {
			cipher, fullKey := doEncryption(iv, randPreKey, pltext)
			most_m0[cipher[0]^(fullKey[2] + 0x02)] += 1
			iv[2] = iv[2] + 0x01
	}
	max := 0;
	var high_m0 byte
	for m0, value := range most_m0 {
		if value > max {
			max = value
			high_m0 = m0
		}
	}
	return high_m0, max
}

func main() {
	iv := []byte{0x01,0xff,0x00}
	rand.Seed(time.Now().UnixNano())
	randPreKey := make([]byte, 13)
	rand.Read(randPreKey)
	pltext, err := exec.Command("openssl", "rand", "-base64", "1").Output()
	if err != nil {
		log.Fatal(err)
	}
	pltext = pltext[:len(pltext)-4]
	fmt.Printf("PlainText: %v\n", pltext)
	fmt.Printf("Key without iv: %v\n", randPreKey)
	fmt.Printf("Guessing m[0] ... ")
	m0, m0high := getM0(iv, randPreKey, pltext)
	fmt.Printf("done\n")
	fmt.Printf("Guessed m[0]=%v (with freq. %v)\n", m0, m0high)
	var dyn byte
	dyn = 0x03
	var j byte
	for j = 0x00; j < 0x0d; j = j + 0x01 {
		fmt.Printf("Guessing k[%v] ... ", j)
		var most_k0 = make(map[byte]int, 256)
		iv2 := []byte{0x03,0xff,0x00}
		dyn = dyn+j+0x03
		iv2[0] = iv2[0] + j
		for i:= 0; i < 256; i++ {
			cipher2, fullKey2 := doEncryption(iv2, randPreKey, pltext)
			most_k0[((cipher2[0]^m0)-fullKey2[2]-dyn)] += 1
			iv2[2] = iv2[2] + 0x01
		}
		max2 := 0;
		var high_k0 byte
		for k0, value := range most_k0 {
			if value > max2 {
				max2 = value
				high_k0 = k0
			}
		}
		fmt.Println("done")
		fmt.Printf("Guessed k[%v]=%v (with freq. %v)   -   ",j, high_k0, max2)
		if high_k0 == randPreKey[j] {
			fmt.Printf("*** OK ***\n")
		} else {
			fmt.Printf("*** WRONG: k[%v] should be: %v***\n", j, randPreKey[j])
		}
		dyn = (dyn + high_k0)
	}

}
