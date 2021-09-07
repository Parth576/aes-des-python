# DES

## Basics

* Plaintext -> 64 bits 
* Ciphertext -> 64 bits
* Key -> 64 bits 
* Based on Feistel network -> dividing input into 2 blocks, processing seperately
* Bit-oriented cipher

## Steps for encryption

* IP - Initial Permutation
* Right & Left Plain Text 
* 16 rounds
* Generating round keys -> initial permutation, split, left rotate
* Each round -> key transformation, permutation, S-box, P-box permutation, swap/XOR
* Final permutation
* 5 modes -> ECB, CBC, CFB, OFB, CTR

## Steps for decryption

* Same as encryption except round keys need to be applied in reverse order

## References

* Padding/Unpadding - https://stackoverflow.com/a/14205319
* https://www.jigsawacademy.com/blogs/cyber-security/des-algorithm/
* https://github.com/kongfy/DES/blob/master/Riv85.txt
* http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
* https://gist.github.com/BlackRabbit-github/2924939
* https://www.nku.edu/~christensen/DESschneier.pdf
* Modes of operation - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

# AES

## Basics

* Block size -> 128 bits
* Keys -> 128, 192, 256 bits
* Rounds -> 10, 12, 14
* Based on subsititution-permutation network
* Byte-oriented cipher
* word -> 4 bytes

## Steps for encryption

* Expansion of encryption key -> key schedule of 44 words
* input state XOR first 4 words of key schedule
* Each round -> Substitute bytes, shift rows, mix columns, add round key 
* Last round does not have mix columns

## Steps for decryption

* cipher state XOR last 4 words of key schedule
* Each round -> Inverse shift rows, inverse Substitute bytes, add round key, inverse mix columns
* Last round does not have inverse mix columns

## References

* https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
* https://www.youtube.com/watch?v=lnKPoWZnNNM
* https://gist.github.com/bonsaiviking/5571001
* https://github.com/boppreh/aes/blob/master/aes.py
* http://anh.cs.luc.edu/331/code/aes.py
* https://github.com/bozhu/AES-Python/blob/master/aes.py
