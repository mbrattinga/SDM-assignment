from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512


class Database():
    def __init__(self) -> None:
        self.storage = {}
        self.doc_counter = 0

    def add(self):
        pass

    def search(self, enc_keyword : bytes, token : bytes) -> [int]:
        """ Perform search of a encrypted keyword

        Args:
            enc_keyword (bytes): the encrypted keyword
            token (bytes): search token

        Returns:
            [int]: return the list of document indexes
        """

        ret = []
        
        for index, keyword_list in self.storage.items():
            for keyword in keyword_list:
                xored = keyword ^ enc_keyword

                left = xored[:12]
                right = PBKDF2(token, "", 4, count=1000, hmac_hash_module=SHA512)
                if (right == xored[12:16]):
                    ret.append(index)


        return ret

    