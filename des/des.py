from typing import List

class DES:

    def __init__(self, plainText:str, key:str) -> None:
        self.plainText = plainText
        self.cipherText = b''
        self.cipherTextArr=[]
        self.key = key
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
        self.initalPlaintextPerm = [
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8,  0,
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6
        ]
        self.expansionTable = [
            31,  0,  1,  2,  3,  4,
             3,  4,  5,  6,  7,  8,
             7,  8,  9, 10, 11, 12,
            11, 12, 13, 14, 15, 16,
            15, 16, 17, 18, 19, 20,
            19, 20, 21, 22, 23, 24,
            23, 24, 25, 26, 27, 28,
            27, 28, 29, 30, 31,  0
        ]
        self.sbox = [
            # S1
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            # S2
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            # S3
            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            # S4
            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            # S5
            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            # S6
            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            # S7
            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            # S8
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
        ]
        self.sboxPerm = [
            15, 6, 19, 20, 28, 11,
            27, 16, 0, 14, 22, 25,
            4, 17, 30, 9, 1, 7,
            23,13, 31, 26, 2, 8,
            18, 12, 29, 5, 21, 10,
            3, 24
        ]
        self.finalPerm = [
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25,
            32,  0, 40,  8, 48, 16, 56, 24
        ]

    def _pad(self, input:bytes) -> bytes:
        length = 8 - (len(input) % 8)
        paddedInput = input
        paddedInput += bytes([length])*length
        return paddedInput

    def _bit2bytes(self, finalArr:List) -> bytes:
        s = ''
        for bit in finalArr:
            s+=str(bit)
        #result = int(s,2).to_bytes(len(s)//8, byteorder='big')
        result = bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))
        return result

    def _getBinArray(self, input:bytes) -> List:
        bitArray = [a for x in input for a in "{0:08b}".format(x) ]
        return bitArray

    def _getBinArrayDecimal(self, input:int) -> List:
        dec2bits = bin(input)[2:]
        if len(dec2bits) < 4:
            extra = '0' * (4-len(dec2bits))
            dec2bits = extra+dec2bits
        result = [str(x) for x in dec2bits]
        return result

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

        # Applying final key permutation to generate the 16 round keys
        for round in range(16):
            newRoundKey = []
            for k in self.finalKeyPerm:
                newRoundKey.append(self.roundKeys[round+1][k])
            self.roundKeys[round+1] = newRoundKey

    def _applyInitialPermutation(self, decrypt:bool) -> List:
        newPlaintextArr = []
        for k in self.initalPlaintextPerm:
            if decrypt:
                newPlaintextArr.append(self.cipherTextArr[k])
            else:
                newPlaintextArr.append(self.plainTextByteArr[k])
        return newPlaintextArr

    def _bitwiseXOR(self, expandedRightBlock:List, roundKey:List) -> List:
        result = []
        for r, k in zip(expandedRightBlock, roundKey):
            result.append(int(r) ^ int(k))
        return result

    def _applySbox(self, xorResult:List) -> List:
        sboxResult = []
        iter = 0
        for i in range(0,48,6):
            roundSbox = self.sbox[iter]
            subArray = xorResult[i:i+6]
            row = str(subArray[0])+str(subArray[5])
            col = str(subArray[1])+str(subArray[2])+str(subArray[3])+str(subArray[4])
            row = int(row,2) # conv to decimal
            col = int(col,2)
            decimalValue = roundSbox[row][col]
            byteArr = self._getBinArrayDecimal(decimalValue) 
            sboxResult+=byteArr
        return sboxResult

    def _applyRoundFunction(self, rightBlock:List, roundKey:List) -> List:
        result = []
        expandedRightBlock = []
        for k in self.expansionTable:
            expandedRightBlock.append(rightBlock[k])
        xorResult = self._bitwiseXOR(expandedRightBlock, roundKey)
        sboxResult = self._applySbox(xorResult)
        for k in self.sboxPerm:
            result.append(sboxResult[k])
        return result
            
    def encrypt(self) -> None:
        pt = self.plainText.encode()
        if len(pt) > 8:
            print("Plaintext should be less than 8 bytes")
            return
        bytesKey = self.key.encode()
        if len(self.key) != 8:
            print("Key should be exactly 8 bytes")
            return
        paddedByteText = self._pad(pt)
        self.plainTextByteArr = self._getBinArray(paddedByteText)
        self.keyByteArr = self._getBinArray(bytesKey)
        self._generateSubkeys()
        permutedPlaintextArr = self._applyInitialPermutation(decrypt=False)

        # left and right arrays to split the plaintext into 32 bits
        l = []
        r = []
        l.append(permutedPlaintextArr[:32])
        r.append(permutedPlaintextArr[32:])

        # 16 rounds start
        for round in range(1,17):
            l.append(r[round-1])
            f = self._applyRoundFunction(r[round-1], self.roundKeys[round])
            xorResult = self._bitwiseXOR(l[round-1],f)
            r.append(xorResult)

        switchArr = r[-1] + l[-1]
        finalResult = []
        for k in self.finalPerm:
            finalResult.append(switchArr[k])
        byteResult = self._bit2bytes(finalResult)
        self.cipherText = byteResult
        print(f'Encrypted Text: {byteResult.decode("unicode_escape")}')

    def decrypt(self) -> None:
        # Decryption is same except that keys are reversed
        self.cipherTextArr = self._getBinArray(self.cipherText)
        permutedCipherTextArr = self._applyInitialPermutation(decrypt=True)

        l = []
        r = []
        l.append(permutedCipherTextArr[:32])
        r.append(permutedCipherTextArr[32:])

        for round in range(1,17):
            l.append(r[round-1])
            f = self._applyRoundFunction(r[round-1], self.roundKeys[17-round])
            xorResult = self._bitwiseXOR(l[round-1],f)
            r.append(xorResult)

        switchArr = r[-1] + l[-1]
        finalResult = []
        for k in self.finalPerm:
            finalResult.append(switchArr[k])
        byteResult = self._bit2bytes(finalResult)
        
        print(f'Decrypted Text: {byteResult.decode("unicode_escape")}')



