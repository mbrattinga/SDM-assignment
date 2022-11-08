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

        # TODO the paper users k1,2,3 for these F,G,P hmacs
    
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


    def SrchToken(self, w):
        Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        return (Fw, Gw, Pw)

    def Search(self, w):
        return self.database.search(self.SrchToken(w))

    # TODO replace all ^ xor operations by correct ones
    def encrypt(self, documents):
        # files = [{0:["keyord1","keyword2"]},{1: ["keyword1"]},{2:[...]},...]
        z = 10000 #TODO

        # calculate total amount of keywords in all provided documents
        total_keywords_amounts = 0
        for _, keywords in documents:
            total_keywords_amounts += len(keywords)

        # initialize data structures
        A_s = [] * (total_keywords_amounts + z) # search array 
        A_d = [] * (total_keywords_amounts + z) # deletion array
        T_s = dict() # search table, maps keywords to the entry document in search array A_s
        T_d = dict() # delete table, maps documents to the keywords in it
        
        zeros = bytes("0" * 16, 'utf-8')


        for doc_id, doc_keywords  in documents:
            temp_doc_id = doc_id
            doc_id = MD5.new(bytes(doc_id, 'utf-8')).digest() # transform to 16 byte, not for security
            myprint("Processing document", temp_doc_id, "with doc_id", doc_id)
            for w in doc_keywords:
                myprint("Processing keyword ", w)
                Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
                
                # find random address in A_s that is not used yet
                while True:
                    addr_s_N = randrange(0, search_array_length -1)
                    if A_s[addr_s_N] == None:
                        break
                
                ri = get_random_bytes(32)
                H1 = SHA256.new(Pw + ri).digest()

                myprint("Going to put this one is A_s[", addr_s_N,"]")


                # If there already is an entry in the search table, decrypt to get that entry, which is the Addr_s(N+1)
                if Fw in T_s:
                    addr_s_N1 = XOR(T_s[Fw], Gw)
                    addr_s_N1 = addr_s_N1[16:] # Addr size is 16, so we do not need the first 16 leading zeros
                    myprint("Already exists an entry in the search table, namely", T_s[Fw])
                    myprint("Therefore we xor this with Gw", Gw, "to obtain ", addr_s_N1)
                else: # Else there is no document with this keyword yet, so Addr(N+1)=0 string as defined in the paper
                    addr_s_N1 = zeros
                    myprint("No entry in the search table exists")
                
                # Put into search table lookup
                T_s[Fw] = XOR(addr_s_N.to_bytes(32,'big'), Gw)
                myprint("Updated search table to ", T_s[Fw], "which is", addr_s_N, "XOR with", Gw)
                
                # Node for search array is ((id || addr(N+1)) ^H1, ri)
                Ni = (XOR(doc_id + addr_s_N1, H1), ri)

                myprint("The node stored in the search array looks like ", Ni)
                myprint("Which before encryption was", doc_id + addr_s_N1, "for doc_id", doc_id, "and address next address", addr_s_N1)
                
                # Store in search array
                A_s[addr_s_N] = Ni


                # 3a
                Pf = HMAC.new(self.key3, msg=doc_id, digestmod=SHA256).hexdigest()
                Kf = Pf

                # TODO deterministc addresses
                
                ri_prime = get_random_bytes(self.consultant.SECURITY_PARAMETER)
                H2 = SHA256.new(Kf + ri_prime)
                Ni = (pad(a_lot_of_shit) ^ H2) + ri_prime
                A_d[A_d_address] = Ni

                # 3b
                Ff = HMAC.new(self.key1, msg=doc_id, digestmod=SHA256).hexdigest()
                Gf = HMAC.new(self.key2, msg=doc_id, digestmod=SHA256).hexdigest()
                T_d[Ff] = A_d_address ^ Gf

        
        # 4 create L_free list
        previous_free = zeros
        for i in range(z):
            
            free = randrange(0, len(A_s))
            while A_s[free] is None:
                free = randrange(0, len(A_s))
            
            A_s[free] = (pad(previous_free, SHA256.block_size),  bytes(bytearray(32))) # TODO this does not include ID?
            previous_free = bytes(str(free), 'utf-8')
        
        T_s["free"] = pad(previous_free, SHA256.block_size)

        

        # 5 fill remain A_s and A_d with random strings of length that fits in A_s
        for i in range(len(A_s)):
            if A_s[i] == None:
                A_s[i] = (get_random_bytes(int(math.ceil(math.log(len(A_s),10)))), get_random_bytes(int(math.ceil(math.log(len(A_s),10)))))

        # 6 encrypt each document using AES
        # TODO leave this for now

        # 7
        self.database.first_setup(A_s, T_s)
        return (A_s,T_s)



