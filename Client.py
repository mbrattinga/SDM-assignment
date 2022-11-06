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
    
    def get_id(self) -> int:
        """ Function to retrieve the id of the client
        Returns:
            int: the client id
        """
        return self.id


    def del_token(K : tuple(bytes, bytes, bytes, bytes), doc_id) -> tuple(bytes, bytes, bytes, int):

        delete_token = F, G, P, doc_id

        return delete_token


    def delete(index, ciphertexts, delete_token):
        self.database.delete(index, ciphertexts, delete_token)
