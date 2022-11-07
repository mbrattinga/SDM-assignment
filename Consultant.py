from Crypto.Random import get_random_bytes

class Consultant():
    def __init__(self, database , sec_param = 2 ** 6):
        self.sec_param = sec_param

        # generate master key
        self.master_key = get_random_bytes(sec_param)
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
        return 