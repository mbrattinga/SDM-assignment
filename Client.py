from Crypto.Hash import HMAC, SHA512
from Consultant import Consultant
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import sys
from Database import Database

class Client():
    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        self.id = id
        self.consultant = consultant
        self.database = database

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
        cipher_AES = AES.new(self.key, AES.MODE_ECB) #deterministic encryption
        s_cipher = AES.new(self.key, AES.MODE_CTR)
        hmac_key = HMAC.new(bytes(self.key), digestmod=SHA512)

        C = list()
        for i in range(len(keywords)):
            W_i = keywords[i]
            X_i = cipher_AES.encrypt(pad(bytes(W_i, 'utf-8'), AES.block_size))
            print("Encrypted keyword",i, X_i)
            # print("Encrypted keyword",i, int.from_bytes(X_i, byteorder='big'))
            S_i = s_cipher.encrypt(pad(bytes(i), AES.block_size))[:12] # is this secure?

            hmac_key = HMAC.new(bytes(self.key), digestmod=SHA512)
            k_i = hmac_key.update(X_i[:12]).digest()
            # T_i = S_i || F_k(S_i)
            T_i = S_i + PBKDF2(k_i, S_i, 4, hmac_hash_module=SHA512)
            C.append(bytes(a ^ b for a,b in zip(X_i, T_i)))

        print("Calculated ciphertext keywords, sending to database...")
        self.database.add(C)
        return C

    # Not working yet
    # def decrypt(self, keywords):
    #     s_cipher = AES.new(self.key, AES.MODE_CTR)
    #     hmac_key = HMAC.new(bytes(self.key), digestmod=SHA512)

    #     W = list()
    #     for i in range(len(keywords)):
    #         C_i = keywords[i]
            
    #         S_i = s_cipher.encrypt(pad(bytes(i), AES.block_size))
    #         k_i = hmac_key.update(X_i[:12]).digest()
    #         T_i = s_hmac.update(i).digest()
    #         W.append(bytes(a ^ b for a,b in zip(C_i, T_i)))

    #     return W

    def search(self, keyword : str):
        cipher_AES = AES.new(self.key, AES.MODE_ECB) #deterministic encryption
        encrypted_keyword = cipher_AES.encrypt(pad(bytes(keyword, 'utf-8'), AES.block_size))

        hmac_key = HMAC.new(bytes(self.key), digestmod=SHA512)
        token = hmac_key.update(encrypted_keyword[:12]).digest()

        print("Searching for keyword ", encrypted_keyword, "with token", token)
        self.database.search(encrypted_keyword, token)
        
    