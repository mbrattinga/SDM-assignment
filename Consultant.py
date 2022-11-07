from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

class Consultant():
    ALLOWED_KEYWORDS = ["cat", "dog","rat","cow","pinguin","giraffe","lion"]
    SECURITY_PARAMETER = 2 ** 6

    def __init__(self, database):
        # generate master key
        self.master_key = get_random_bytes(self.SECURITY_PARAMETER)
        print("Master key:", self.master_key)

        # set database
        self.database = database


    def key_gen(self, client_id : int) -> bytes:
        """ Function to generate a key for a specific client.
        Args:
            client_id (int): the client's id.
        Returns:
            bytes: the private key of the client.
        """
        salt = client_id.to_bytes(4, byteorder='big')
        key = PBKDF2(self.master_key, salt, 32, count=1000000, hmac_hash_module=SHA512)
        return key

    def write(self, keywords):
        pass

    def search(self, keyword):
        pass
