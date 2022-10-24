from Crypto.Hash import HMAC, SHA512
from Consultant import Consultant
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

class Client():
    def __init__(self, id : int, consultant : Consultant) -> None:
        self.id = id
        self.consultant = consultant

        self.key = self.consultant.key_gen(self.id) # get private key 

    def get_id(self) -> int:
        """ Function to retrieve the id of the client

        Returns:
            int: the client id
        """
        return self.id

    def get_key(self) -> bytes:
        """ Function to retrieve the private key of the client

        Returns:
            bytes: the client's private key
        """
        return self.key

    def write(self, keywords):
        cipher_AES = AES.new(self.key, AES.MODE_ECB)

        C = list()
        for i in range(len(keywords)):
            X_i = cipher_AES.encrypt(pad(bytes(keywords[i], 'utf-8'), 16))

            hmac = HMAC.new(bytes(self.key), digestmod=SHA512)
            k_i = hmac.update(X_i[:12]).digest()
            # T_i = S_i || F_k(S_i)
            T_i = get_random_bytes(12) + PBKDF2(k_i, "", 4, hmac_hash_module=SHA512)
            C.append((int.from_bytes(X_i, byteorder='big') ^ int.from_bytes(T_i, byteorder='big')).to_bytes(16, byteorder='big'))

        return C

    def decrypt(self, keywords):
        cipher_AES = AES.new(self.key, AES.MODE_ECB)

        W = list()
        for i in range(len(keywords)):
            C_i = keywords[i]
            
            hmac = HMAC.new(bytes(self.key), digestmod=SHA512)
            k_i = hmac.update(X_i[:12]).digest()
            # T_i = S_i || F_k(S_i)
            T_i = 0
            W.append((int.from_bytes(C_i, byteorder='big') ^ int.from_bytes(T_i, byteorder='big')).to_bytes(16, byteorder='big'))

        return W

    def search(self, keyword : str):
        pass
    