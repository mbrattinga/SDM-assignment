from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, HMAC, SHA256, MD5
from Util import XOR
from Database import Database

class Consultant():
    SECURITY_PARAMETER = 2 ** 8

    def __init__(self, database: Database):
        """_summary_

        Args:
            database (Database): The database the client interacts with
        """

        # generate master key
        self.master_key = get_random_bytes(self.SECURITY_PARAMETER)

        # set database
        self.database = database

        # create a cache for the keys
        self.keycache = dict()

    def key_gen(self, client_id : int) -> bytes:
        """ Generate a key for a specific client, asuming the client is authenticated and authorized to get the specific key
        Args:
            client_id (int): the client's id.
        Returns:
            bytes: the private key of the client.
        """

        salt = client_id.to_bytes(4, byteorder='big')
        key = PBKDF2(self.master_key, salt, 32, count=1000000, hmac_hash_module=SHA512)
        self.keycache[client_id] = key
        return key

    def add_token(self, document, client_id: int):
        """Creates an token that allows the consultant to add the given document for the given client_id to the database.

        Args:
            document ((str, [str, ...])): document tuple containg the identifier and a list of keywords
            client_id (int): the id of the client to which the document belongs

        Returns:
            ([bytes]): the add token for the given document for the given client id
        """

        # check if we have cached the symmetric key for this client, otherwise generate one
        if client_id in self.keycache:
            key = self.keycache[client_id]
        else:
            key = self.key_gen(client_id)
        
        # generate the three subkeys for this client
        key1 = PBKDF2(key, 1, 32, count=1000000, hmac_hash_module=SHA512)
        key2 = PBKDF2(key, 2, 32, count=1000000, hmac_hash_module=SHA512)
        key3 = PBKDF2(key, 3, 32, count=1000000, hmac_hash_module=SHA512)

        # encode the document identifier
        doc_id = MD5.new(bytes(document[0], 'utf-8')).digest() # transform to 16 byte, not for security
        zeros = bytearray(16)
        lambdas = list()
        
        # for each keyword in the document, create lambda
        for w in document[1]:
            Fw = HMAC.new(key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
            Gw = HMAC.new(key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
            Pw = HMAC.new(key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
            ri = get_random_bytes(32)

            H1 = SHA256.new(Pw + ri).digest()

            lambda_i = Fw + Gw + XOR(doc_id + zeros, H1) + ri
            lambdas.append(lambda_i)

        return lambdas

    def add(self, document, client_id: int):
        """Adds the given document belonging to the given client id to the database

        Args:
            document ((str, [str, ...])): document tuple containg the identifier and a list of keywords
            client_id (int): the id of the client to which the document belongs

        Returns:
            bool: True if the addition was succesfull, otherwise False
        """

        # calculate the add token, and pass to the database
        return self.database.add(self.add_token(document, client_id))

    def search(self, w: str, client_id: int):
        """Return document identifiers of documents in the database that belong to the given client id and contain the given keyword

        Args:
            w (str): the keyword to search for
            client_id (int): the id of the client to which the document belongs

        Returns:
            [str]: list of documents that belong to the client with the given id and contain the keyword
        """

        # calculate search token, and pass to the database
        return self.database.search(self.search_token(w, client_id))
        
    
    def search_token(self, w: str, client_id: int):
        """Generates an token that allows to search for documents belong to the client with the given client id and contain the search keyword

        Args:
            w (str): search keyword
            client_id (int): the id of the client in who's documents to search

        Returns:
            (bytes, bytes, bytes): search token that allows to search for documents belong to the client with the given client id and contain the search keyword
        """

        # check if we have cached the symmetric key for this client, otherwise generate one
        if client_id in self.keycache:
            key = self.keycache[client_id]
        else:
            key = self.key_gen(client_id)
        
        # generates three subkeys for this client
        key1 = PBKDF2(key, 1, 32, count=1000000, hmac_hash_module=SHA512)
        key2 = PBKDF2(key, 2, 32, count=1000000, hmac_hash_module=SHA512)
        key3 = PBKDF2(key, 3, 32, count=1000000, hmac_hash_module=SHA512)

        # compute the three parts of the search token
        Fw = HMAC.new(key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Gw = HMAC.new(key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Pw = HMAC.new(key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        return (Fw, Gw, Pw)