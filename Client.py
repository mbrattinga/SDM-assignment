from ast import keyword
import math
from Database import Database
from Consultant import Consultant
from Crypto.Hash import SHA256, HMAC, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange
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

        # TODO the paper users k1,2,3 for these F,G,P hmac

    
    def get_id(self) -> int:
        """ Function to retrieve the id of the client
        Returns:
            int: the client id
        """
        return self.id


    # TODO replace all ^ xor operations by correct ones
    def encrypt(self, documents):
        # files = [("0", ["keyord1","keyword2"]),("1", ["keyword1"]),("2",[...]),...]
        z = 10000 #TODO

        # calculate total amount of keywords in all provided documents
        total_keywords_amounts = 0
        for _, keywords in documents:
            total_keywords_amounts += len(keywords)

        print("DEBUG", "total_keywords_amount", total_keywords_amounts)

        # initialize data structures
        search_array_length = (total_keywords_amounts + z)
        A_s = [None] * search_array_length # search array 
        T_s = dict() # search table, maps keywords to the entry document in search array A_s
        
        zeros = "0" * int(math.ceil(math.log((search_array_length))))


        for doc_id, doc_keywords  in documents:
            for w in doc_keywords:
                Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()

                
                # find random address in A_s that is not used yet
                while True:
                    addr_s_N = randrange(0, search_array_length -1)
                    print(addr_s_N, len(A_s))
                    if A_s[addr_s_N] is None:
                        break
                
                ri = get_random_bytes(self.consultant.SECURITY_PARAMETER)
                H1 = SHA256.new(Pw + ri).digest()


                # If there already is an entry in the search table, decrypt to get that entry, which is the Addr_s(N+1)
                if Fw in T_s:
                    addr_s_N1 = T_s[Fw] ^ Gw
                else: # Else there is no document with this keyword yet, so Addr(N+1)=0 string as defined in the paper
                    addr_s_N1 = zeros
                
                # Node for search array is ((id || addr(N+1)) ^H1, ri)
                Ni = (bytes(a ^ b for a,b in zip(pad(bytes(doc_id + addr_s_N1, 'utf-8'), SHA256.block_size), H1)), ri)
                
                
                # Store in search array
                A_s[addr_s_N] = Ni

        
        # 4 create L_free list
        previous_free = zeros
        for i in range(z):
            while True:
                free = randrange(0, len(A_s))
                if A_s[free] is None:
                    break
            
            A_s[free] = pad(bytes(previous_free, 'utf-8'), SHA256.block_size)
            previous_free = str(free)
        
        T_s["free"] = pad(bytes(previous_free, 'utf-8'), SHA256.block_size)

        

        # 5 fill remain A_s and A_d with random strings of length that fits in A_s
        for i in range(len(A_s)):
            if A_s[i] is None:
                A_s[i] = get_random_bytes(int(math.ceil(math.log(len(A_s),10))))

        # 6 encrypt each document using AES
        # TODO leave this for now

        # 7
        return (A_s,T_s)



