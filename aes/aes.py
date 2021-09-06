from typing import List

class AES:

    def __init__(self, plainText:str, key:str) -> None:
        self.plainText = plainText
        self.key = key
        self.keyBytes = b''

    def __pad(self, input:bytes) -> bytes:
        length = 16 - (len(input) % 16)
        paddedInput = input
        paddedInput += bytes([length])*length
        return paddedInput

    def __unpad(self, input:bytes) -> bytes:
        unpadInput = input[:-input[-1]]
        return unpadInput

    def __leftRotate(self, arr:bytes, n) -> bytes:
        n = n % len(arr)
        return arr[n:] + arr[:n]

    def __g(self, word:bytes) -> bytes:
        result = b''
        rotatedWord = self.__leftRotate(word,1)
        return result



    def __generateRoundKeys(self) -> None:
        # 16 byte key divided into 4 words
        w0 = self.key[:4]
        w1 = self.key[4:8]
        w2 = self.key[8:12]
        w3 = self.key[12:16]


    def encrypt(self) -> None:
        pt = self.plainText.encode()
        if len(pt) > 16:
            print("Plaintext should be less than 16 bytes")
            return
        bytesKey = self.key.encode()
        self.keyBytes = bytesKey
        if len(bytesKey) != 16:
            print("Key should be exactly 16 bytes")
            return
        paddedByteText = self.__pad(pt)
        self.__generateRoundKeys()

    def decrypt(self) -> None:
        pass


