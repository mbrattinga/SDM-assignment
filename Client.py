import math
from Database import Database
from Consultant import Consultant
from Crypto.Hash import SHA256, HMAC, SHA512, MD5
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Util import XOR, myprint

class Client():

    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        """Initialize a client with the given id, that interacts with the given consultant and database

        Args:
            id (int): the id of this client
            consultant (Consultant): the consultant with whom the client interacts
            database (Database): the database with whom the client interacts
        """
        self.id = id
        self.consultant = consultant
        self.database = database

        # request symmetric key and derive subkeys
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



    def srch_token(self, w: str):
        """Generates an token that allows to search for documents belong to this client and contain the search keyword

        Args:
            w (str): search keyword

        Returns:
            (bytes, bytes, bytes): search token that allows to search for documents belong to this client and contain the search keyword
        """

        # compute the three parts of the search token
        Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        return (Fw, Gw, Pw)

    def search(self, w: str):
        """Return document identifiers of documents in the database that belong to this client and contain the given keyword

        Args:
            w (str): the keyword to search for

        Returns:
            [str]: list of documents that belong to this client and contain the keyword
        """
        return self.database.search(self.srch_token(w))


    def add_token(self, document):
        """Creates an token that allows the client to add the given document to the database.

        Args:
            document ((str, [str, ...])): document tuple containg the identifier and a list of keywords

        Returns:
            ([bytes]): the add token for the given document for this client
        """

        # encode the document identifier
        doc_id = MD5.new(bytes(document[0], 'utf-8')).digest() # transform to 16 byte, not for security
        zeros = bytearray(16)
        lambdas = list()

        # for each keyword in the document, create lambda
        for w in document[1]:
            Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
            Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
            Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
            ri = get_random_bytes(32)

            H1 = SHA256.new(Pw + ri).digest()

            lambda_i = Fw + Gw + XOR(doc_id + zeros, H1) + ri
            lambdas.append(lambda_i)

        return lambdas

    def add(self, document):
        """Adds the given document to the database

        Args:
            document ((str, [str, ...])): document tuple containg the identifier and a list of keywords

        Returns:
            bool: True if the addition was succesfull, otherwise False
        """
        return self.database.add(self.add_token(document))


    def encrypt(self, documents):
        """Creates an initial datastructure based on the given documents

        Args:
            documents ([(str, [str])])): list of documents, which are tuples with their identifier and list of keywords

        Returns:
            ([bytes], dict): search array and search table
        """
        z = 10000 # free space in the search array

        # calculate total amount of keywords in all provided documents
        total_keywords_amounts = 0
        for _, keywords in documents:
            total_keywords_amounts += len(keywords)

        # 1. initialize data structures
        search_array_length = (total_keywords_amounts + z)
        A_s = [None] * search_array_length # search array 
        T_s = dict() # search table, maps keywords to the entry document in search array A_s
        
        zeros = bytearray(16)

        # 2. process each document and generate the search array and table
        for doc_id, doc_keywords  in documents:
            # encode document id
            temp_doc_id = doc_id
            doc_id = MD5.new(bytes(doc_id, 'utf-8')).digest() # transform to 16 byte, not for security

            # for each keyword in the current document
            for w in doc_keywords:
                Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                
                # find random address in A_s that is not used yet
                # simulates a pseudorandom permutation
                while True:
                    addr_s_N = randrange(0, search_array_length -1)
                    if A_s[addr_s_N] == None:
                        break
                
                ri = get_random_bytes(32)
                H1 = SHA256.new(Pw + ri).digest()

                # Check and get if there is an entry in the search table
                if Fw in T_s:
                    addr_s_N1 = XOR(T_s[Fw], Gw) # decrypt search table entry
                    addr_s_N1 = addr_s_N1[16:] # Addr size is 16, so we do not need the first 16 leading zeros
                else: # there is no document with this keyword yet, so Addr(N+1)=00.. as defined in the paper
                    addr_s_N1 = zeros
                
                # Put into search table
                T_s[Fw] = XOR(addr_s_N.to_bytes(32,'big'), Gw)
    
                # encrypt node for search array: ((id || addr(N+1)) ^H1, ri)
                Ni = (XOR(doc_id + addr_s_N1, H1), ri)

                # store in search array
                A_s[addr_s_N] = Ni

        
        # 4. create a linked list of free spots in the search array
        previous_free = bytearray(32)
        for i in range(z):
            # find a free spot in the search array
            while True:
                free = randrange(0, len(A_s))
                if A_s[free] is None:
                    break
            
            A_s[free] = (previous_free,  bytes(bytearray(32)))
            previous_free = free.to_bytes(32, 'big')
        
        T_s["free"] = previous_free

        

        # 5. fill remain A_s and A_d with random strings of length that fits in A_s
        for i in range(len(A_s)):
            if A_s[i] == None:
                A_s[i] = (get_random_bytes(int(math.ceil(math.log(len(A_s),10)))), get_random_bytes(int(math.ceil(math.log(len(A_s),10)))))

        # 6 encrypt each document using AES
        # TODO not used in our version, we solely work with identifiers

        # 7 call the database with our encrypted search array and table
        self.database.first_setup(A_s, T_s)
        return (A_s,T_s)



