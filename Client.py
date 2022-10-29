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