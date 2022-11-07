import math
from Database import Database
from Consultant import Consultant
from Crypto.Hash import SHA256, HMAC, SHA512
from Crypto.Random import get_random_bytes, randrange
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

class Client():

    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        self.id = id
        self.consultant = consultant
        self.database = database

        self.key = self.consultant.key_gen(self.id) #k4
        self.key1 = PBKDF2(self.key, 1, 32, count=1000000, hmac_hash_module=SHA512)
        self.key2 = PBKDF2(self.key, 2, 32, count=1000000, hmac_hash_module=SHA512)
        self.key3 = PBKDF2(self.key, 3, 32, count=1000000, hmac_hash_module=SHA512)

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

        F = HMAC.new(K[0], msg=doc_id, digestmod=SHA256).hexdigest()
        G = HMAC.new(K[1], msg=doc_id, digestmod=SHA256).hexdigest()
        P = HMAC.new(K[2], msg=doc_id, digestmod=SHA256).hexdigest()
        delete_token = F, G, P, doc_id

        return delete_token


    # def delete(index, ciphertexts, delete_token):
    def delete(delete_token):
        self.database.delete(delete_token)

    # TODO replace all ^ xor operations by correct ones
    def encrypt(self, documents : {int : list[str]}):
        # files = [{0:["keyord1","keyword2"]},{1: ["keyword1"]},{2:[...]},...]
        z = 10000 #TODO

        # calculate total amount of keywords in all provided documents
        total_keywords_amounts = 0
        for _, keywords in documents.items():
            total_keywords_amounts += len(keywords)

        # initialize data structures
        A_s = [] * (total_keywords_amounts + z) # search array 
        # A_d = [] * (total_keywords_amounts + z) # deletion array
        T_s = dict() # search table, maps keywords to the entry document in search array A_s [bytes -> bytes]
        # T_d = dict() # deletion table, maps documents to the entry position in deletion array A_d [bytes -> bytes]

        # Check which document contains keyword w_i for each possible keyword, as defined by the TTP
        for i, w in enumerate(Consultant.ALLOWED_KEYWORDS): 
            Fw = HMAC.new(self.key1, msg=w, digestmod=SHA256).hexdigest()
            Gw = HMAC.new(self.key2, msg=w, digestmod=SHA256).hexdigest()
            Pw = HMAC.new(self.key3, msg=w, digestmod=SHA256).hexdigest()
            Kw = Pw 
            for doc_id, doc_keywords in documents.items():
                if w in doc_keywords:
                    # Adding this document to Lw (pseudocode)

                    # find random address in A_s that is not used yet
                    # TODO make this a pseudorandom function
                    while True:
                        A_s_address = randrange(len(A_s))
                        if A_s[A_s_address] is None:
                            break

                    # (2a) calculate Ni and store in search array
                    ri = get_random_bytes(self.consultant.SECURITY_PARAMETER)
                    addr_s_Nplus = 0 # TODO how can we possibly now this one already?
                    H1 = SHA256.new(Kw + ri)
                    Ni = (pad(doc_id + addr_s_Nplus) ^ H1) + ri
                    A_s[A_s_address] = Ni

                    # (2b)
                    # store a pointer to the first node of L_w
                    T_s[Fw] = (A_s_address) ^ Gw #  + A_d_address
        
        # 4 create L_free list
        

        # 5 fill remain A_s and A_d with random strings of length that fits in A_s
        for i in range(len(A_s)):
            if A_s[i] is None:
                A_s[i] = get_random_bytes(int(math.ceil(math.log(len(A_s),10))))

        # 6 encrypt each document using AES
        c = list()
        for document in documents:
            c.append(document) # TODO AES encryption of keywords

        # 7
        return ((A_s,T_s), c)



