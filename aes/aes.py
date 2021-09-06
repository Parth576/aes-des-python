from typing import List

class AES:

    def __init__(self, plainText:str, key:str) -> None:
        self.plainText = plainText
        self.key = key

    def _pad(self, input:bytes) -> bytes:
        length = 8 - (len(input) % 8)
        paddedInput = input
        paddedInput += bytes([length])*length
        return paddedInput

    def _unpad(self, input:bytes) -> bytes:
        unpadInput = input[:-input[-1]]
        return unpadInput

    def _leftRotate(self, arr, n) -> List:
        n = n % len(arr)
        return arr[n:] + arr[:n]

    def encrypt(self) -> None:
        pt = self.plainText.encode()
        if len(pt) > 8:
            print("Plaintext should be less than 8 bytes")
            return
        bytesKey = self.key.encode()
        if len(bytesKey) != 8:
            print("Key should be exactly 8 bytes")
            return
        paddedByteText = self._pad(pt)

    def decrypt(self) -> None:
        pass


