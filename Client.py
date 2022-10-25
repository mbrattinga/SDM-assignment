from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from Consultant import Consultant
from Database import Database

class Client():
    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        self.id = id
        self.consultant = consultant
        self.database = database

        self.key = self.consultant.key_gen(self.id) # get private key 

        self.E_cipher = AES.new(self.key, AES.MODE_ECB) #deterministic encryption


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

    def write(self, keywords : [str]) -> [bytes]:
        """ Function used by the client to write data on the database.

        Args:
            keywords (str]): the list of keywords that we user wants to write.

        Returns:
            [bytes]: the encryped keywords that have been written.
        """
        
        s_cipher = AES.new(self.key, AES.MODE_CTR)

        C = []
        for i, keyword in enumerate(keywords):
            W_i = pad(bytes(keyword, 'utf-8'), AES.block_size)
            X_i = self.E_cipher.encrypt(W_i)
            L_i, R_i = X_i[:12], X_i[12:]

            f_cipher = HMAC.new(self.key, digestmod=SHA256)
            k_i = f_cipher.update(L_i).digest() #silver key
            S_i = s_cipher.encrypt(pad(bytes(i), AES.block_size))[:12] # is this secure?
            F_cipher = AES.new(k_i, AES.MODE_ECB)

            # T_i = S_i || F_k(S_i)
            F_S = F_cipher.encrypt(pad(S_i, AES.block_size))[:4]
            T_i = S_i + F_S
            C_i = bytes(a ^ b for a,b in zip(X_i, T_i))
            C.append(C_i)
        self.database.add(C)
        return C

    # Not working yet
    # def decrypt(self, keywords):
    #     s_cipher = AES.new(self.key, AES.MODE_CTR)
    #     hmac_key = HMAC.new(bytes(self.key), digestmod=SHA512)

    #     W = list()
    #     for i, keyword in enumerate(keywords):
    #         C_i = keyword
            
    #         S_i = s_cipher.encrypt(pad(bytes(i), AES.block_size))
    #         k_i = hmac_key.update(X_i[:12]).digest()
    #         T_i = s_hmac.update(i).digest()
    #         W.append(bytes(a ^ b for a,b in zip(C_i, T_i)))

        return W

    def search(self, keyword : str):
        """ Function of the client to search on the database.

        Args:
            keyword (str): the keyword in plaintext to be searched. 

        Returns:
            [int]: the list of document indexes that contain the keyword. 
        """
        X = self.E_cipher.encrypt(pad(bytes(keyword, 'utf-8'), AES.block_size))
        L_i, R_i = X[:12], X[12:]

        f_cipher = HMAC.new(self.key, digestmod=SHA256)
        k_i = f_cipher.update(L_i).digest() #search token
        return self.database.search(X, k_i)
        
    
    def get_E_cipher(self):
        """ Helper function the retrieve the encryption function used by the client.
        """
        return self.E_cipher
