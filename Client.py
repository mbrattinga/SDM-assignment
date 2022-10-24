from Consultant import Consultant

class Client():
    def __init__(self, id : int, consultant : Consultant) -> None:
        self.id = id
        self.consultant = consultant

        # get private key 
        self.key = self.consultant.ken_gen(self.id)

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

    def write(self, message : str):
        pass

    def search(self, keyword : str):
        pass
    