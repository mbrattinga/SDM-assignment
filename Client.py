from Consultant import Consultant
from Database import Database

class Client():
    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        self.id = id
        self.consultant = consultant
        self.database = database

        # get private key 
        self.key = self.consultant.key_gen(self.id)


    def getId(self) -> int:
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

    def write(self, message : str, database : Database):
        database.add()

    def search(self, keyword : str, database : Database):
        database.search()
    