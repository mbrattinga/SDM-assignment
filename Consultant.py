from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, HMAC, SHA256

class Consultant():
    ALLOWED_KEYWORDS = ["cat", "dog","rat","cow","pinguin","giraffe","lion"]
    SECURITY_PARAMETER = 2 ** 6

    def __init__(self, database):
        # generate master key
        self.master_key = get_random_bytes(self.SECURITY_PARAMETER)
        print("Master key:", self.master_key)

        # set database
        self.database = database

        self.keycache = dict() #TODO do we want a key cache?

    def key_gen(self, client_id : int) -> bytes:
        """ Function to generate a key for a specific client.
        Args:
            client_id (int): the client's id.
        Returns:
            bytes: the private key of the client.
        """
        salt = client_id.to_bytes(4, byteorder='big')
        key = PBKDF2(self.master_key, salt, 32, count=1000000, hmac_hash_module=SHA512)
        self.keycache[client_id] = key
        return key

    def write(self, keywords):
        pass

    def search(self, keyword, client_id: int):
        return self.database.search(self.search_token(keyword, client_id))
        
    
    def search_token(self, w, client_id: int):
        if client_id in self.keycache:
            key = self.keycache[client_id]
        else:
            key = self.key_gen(client_id)
        
        # TODO this is very slow to do for each search query...
        key1 = PBKDF2(key, 1, 32, count=1000000, hmac_hash_module=SHA512)
        key2 = PBKDF2(key, 2, 32, count=1000000, hmac_hash_module=SHA512)
        key3 = PBKDF2(key, 3, 32, count=1000000, hmac_hash_module=SHA512)

        Fw = HMAC.new(key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Gw = HMAC.new(key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Pw = HMAC.new(key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        return (Fw, Gw, Pw)
