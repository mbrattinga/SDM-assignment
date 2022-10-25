from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad

# from Client import Client

class Consultant():
    def __init__(self, database , sec_param = 2 ** 6):
        self.sec_param = sec_param

        # generate master key
        self.master_key = get_random_bytes(sec_param)
        print("Master key:", self.master_key)

        # set database
        self.database = database

    
    # https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html
    # it's pretty slow
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
    

    def write(self, client, keywords : [str]) -> [bytes]:
        """Function used by the consultant to write data on the database on behalf
           or a client.

        Args:
            client (Client): the istance of the client that the consultant wishes
                             to write for.
            keywords (str]): the keyword in plaintext to be searched. 

        Returns:
            [bytes]: the encryped keywords that have been written.
        """
        user_key = self.key_gen(client.get_id())

        E_cipher = client.get_E_cipher()
        s_cipher = AES.new(user_key, AES.MODE_CTR)

        C = []
        for i, keyword in enumerate(keywords):
            W_i = pad(bytes(keyword, 'utf-8'), AES.block_size)
            X_i = E_cipher.encrypt(W_i)
            L_i, R_i = X_i[:12], X_i[12:]
    
            f_cipher = HMAC.new(user_key, digestmod=SHA256)
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
    

    def search(self, client, keyword : str) -> [int]:
        """Function of the consultant to search on the database for a specific client.

        Args:
            client (Client): the istance of the client that the consultant wishes
                             to search for.
            keyword (str): the keyword in plaintext to be searched. 

        Returns:
            [int]: the list of document indexes that contain the keyword. 
        """
        user_key = self.key_gen(client.get_id())
        # E_cipher = AES.new(user_key, AES.MODE_ECB) 
        E_cipher = client.get_E_cipher()

        X = E_cipher.encrypt(pad(bytes(keyword, 'utf-8'), AES.block_size))
        L_i, R_i = X[:12], X[12:]

        f_cipher = HMAC.new(user_key, digestmod=SHA256)
        k_i = f_cipher.update(L_i).digest() #search token
        return self.database.search(X, k_i)