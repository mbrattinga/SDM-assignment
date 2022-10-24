from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Database():
    def __init__(self) -> None:
        self.storage = {}
        self.doc_counter = 0

    def add(self, c_keywords):
        self.storage[self.doc_counter] = c_keywords
        print("Database: added new document with keywords, with ID", self.doc_counter)
        self.doc_counter += 1

    def search(self, enc_keyword : bytes, token : bytes):
        """ Perform search of a encrypted keyword
        Args:
            enc_keyword (bytes): the encrypted keyword
            token (bytes): search token
        Returns:
            [int]: return the list of document indexes
        """
        F_cipher = AES.new(token, AES.MODE_CBC)

        ret = []
        
        for index, keyword_list in self.storage.items():
            for keyword in keyword_list:
                xored = bytes(a ^ b for a,b in zip(keyword, enc_keyword))

                left = xored[:12]
                
                right = F_cipher.encrypt(pad(left, AES.block_size))
                # right = PBKDF2(token, left, 4, count=1000, hmac_hash_module=SHA512)
                if (right == xored[12:16]):
                    ret.append(index)


        return ret

    