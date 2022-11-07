from Database import Database
from Consultant import Consultant

class Client():

    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        self.id = id
        self.consultant = consultant
        self.database = database

        # client's lookup table 
        # { keyword : list of document id containing that keyword }
        self.lookup_table = {}

        self.key = self.consultant.key_gen(self.id) #k4
        self.key1 = PBKDF2(self.key, 1, 32, count=1000000, hmac_hash_module=SHA512)
        self.key2 = PBKDF2(self.key, 2, 32, count=1000000, hmac_hash_module=SHA512)
        self.key3 = PBKDF2(self.key, 3, 32, count=1000000, hmac_hash_module=SHA512)
    
    def get_id(self) -> int:
        """ Function to retrieve the id of the client
        Returns:
            int: the client id
        """
        return self.id

    

    def del_token(K : tuple(bytes, bytes, bytes, bytes), doc_id) -> tuple(bytes, bytes, bytes, int):

        F = HMAC.new(K[0], msg=doc_id, digestmod=SHA256).hexdigest()
        G = HMAC.new(K[1], msg=doc_id, digestmod=SHA256).hexdigest()
        P = HMAC.new(K[2], msg=doc_id, digestmod=SHA256).hexdigest()
        delete_token = F, G, P, doc_id

        return delete_token


    # def delete(index, ciphertexts, delete_token):
    def delete(delete_token):
        self.database.delete(delete_token)
