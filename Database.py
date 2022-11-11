from operator import xor
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Database():
    def __init__(self) -> None:
        self.storage = {}
        self.doc_counter = 0

    def add(self, c_keywords : [bytes]):
        """ Performs add an encrypted document on the database.

        Args:
            c_keywords ([bytes]): the encryped keywords of the document.
        Returns:
            int: the identifier of the document added
        """
        self.storage[self.doc_counter] = c_keywords
        self.doc_counter += 1
        return self.doc_counter - 1

    def search(self, X : bytes, token : bytes) -> [int]:
        """ Performs search of an encrypted keyword.
        Args:
            enc_keyword (bytes): the encrypted keyword.
            token (bytes): search token.
        Returns:
            [int]: return the list of document indexes that contain the keyword.
        """
        F_cipher = AES.new(token, AES.MODE_ECB)

        result = []
        
        for index, keyword_list in self.storage.items():
            for C_i in keyword_list:
                T = bytes(a ^ b for a,b in zip(C_i, X))

                S, F_S = T[:12], T[12:16]
                calculated_right = F_cipher.encrypt(pad(S, AES.block_size))[:4]
                if (bytearray(F_S) == bytearray(calculated_right)):
                    result.append(index)
                    break

        return result


    def get_storage(self) -> {}:
        """ Helper function to retrieve the encrypted storage.

        Returns:
            dict: the storage.
        """
        return self.storage

    