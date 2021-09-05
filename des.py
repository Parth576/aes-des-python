from typing import List


class DES:

    def __init__(self, plainText:str) -> None:
        self.plainText = plainText
        self.cipherText = ""
        self.plainTextByteArr = []
        self.keyByteArr = []
        self.permKeyArr = []
        self.initalKeyPerm = [
            56, 48, 40, 32, 24, 16,  8,
		    0, 57, 49, 41, 33, 25, 17,
		    9,  1, 58, 50, 42, 34, 26,
		    18, 10,  2, 59, 51, 43, 35,
		    62, 54, 46, 38, 30, 22, 14,
		    6, 61, 53, 45, 37, 29, 21,
		    13,  5, 60, 52, 44, 36, 28,
		    20, 12,  4, 27, 19, 11,  3
	    ]
        self.keyRotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1] #Number of bits to rotate each key
        self.roundKeys = {} # Dictionary of 16 round keys with round number as key and key as value
        self.finalKeyPerm = [
            13, 16, 10, 23,  0,  4,
             2, 27, 14,  5, 20,  9,
            22, 18, 11,  3, 25,  7,
            15,  6, 26, 19, 12,  1,
            40, 51, 30, 36, 46, 54,
            29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52,
            45, 41, 49, 35, 28, 31
        ]

    def _pad(self, input:bytes) -> bytes:
        length = 8 - (len(input) % 8)
        paddedInput = input
        paddedInput += bytes([length])*length
        return paddedInput

    def _getBinArray(self, input:bytes) -> List:
        bitArray = [a for x in input for a in "{0:08b}".format(x) ]
        return bitArray

    def _unpad(self, input:bytes) -> bytes:
        unpadInput = input[:-input[-1]]
        return unpadInput

    def _leftRotate(self, arr, n) -> List:
        n = n % len(arr)
        return arr[n:] + arr[:n]

    def _generateSubkeys(self) -> None:
        # Converting key to 56 bits according to initalKeyPerm
        newKey = []
        for k in self.initalKeyPerm:
            newKey.append(self.keyByteArr[k])
        self.permKeyArr = newKey
        c = []
        d = []
        c0 = self.permKeyArr[:28] # first 28 bits
        d0 = self.permKeyArr[28:] # next 28 bits

        # first round key
        c.append(self._leftRotate(c0, self.keyRotations[0]))
        d.append(self._leftRotate(d0, self.keyRotations[0]))
        self.roundKeys[1] = c[0] + d[0]

        # Generating 16 round keys and storing them in dict
        for ctr in range(1,16):
            c.append(self._leftRotate(c[ctr-1], self.keyRotations[ctr]))
            d.append(self._leftRotate(d[ctr-1], self.keyRotations[ctr]))
            self.roundKeys[ctr+1] = c[ctr] + d[ctr]
        print("Round keys generated successfully")
            
    def encrypt(self, key) -> None:
        pt = self.plainText.encode()
        if len(pt) > 8:
            print("Plaintext should be less than 8 bytes")
            return
        bytesKey = key.encode()
        if len(key) != 8:
            print("Key should be exactly 8 bytes")
            return
        paddedByteText = self._pad(pt)
        self.plainTextByteArr = self._getBinArray(paddedByteText)
        self.keyByteArr = self._getBinArray(bytesKey)
        self._generateSubkeys()
        print(self.roundKeys)
        

    def decrypt(self) -> None:
        pass
