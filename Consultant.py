from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

class Consultant():
    def __init__(self, sec_param = 2 ** 6) -> None:
        self.sec_param = sec_param

        # generate master key
        self.master_key = get_random_bytes(sec_param)
        print("Master key: ", self.master_key)

    
    # https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
    def key_gen(self, client_id : int) -> bytes:
        salt = get_random_bytes(16)
        key = PBKDF2(self.master_key, salt, 32, count=1000000, hmac_hash_module=SHA512)
        return key
    

    def write(self, client_id : int):
        pass
    

    def search(self, client_id : int, keyword : str):
        pass