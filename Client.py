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
        # self.lookup_table = {}

        # TODO the paper users k1,2,3 for these F,G,P hmacs
    
    def get_id(self) -> int:
        """ Function to retrieve the id of the client
        Returns:
            int: the client id
        """
        return self.id

    

    def del_token(self, doc : tuple()) -> tuple([bytes, bytes, bytes, tuple()]):
        Ff = HMAC.new(self.key1, msg=bytes(doc[0], 'utf-8'), digestmod=SHA256).hexdigest()
        Gf = HMAC.new(self.key2, msg=bytes(doc[0], 'utf-8'), digestmod=SHA256).hexdigest()
        Pf = HMAC.new(self.key3, msg=bytes(doc[0], 'utf-8'), digestmod=SHA256).hexdigest()
        delete_token = Ff, Gf, Pf, doc

        return delete_token


    # def delete(index, ciphertexts, delete_token):
    def delete(self, doc):
        delete_token = self.del_token(doc)
        self.database.delete(delete_token)


    def srch_token(self, w):
        Fw = HMAC.new(self.key1, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Gw = HMAC.new(self.key2, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        Pw = HMAC.new(self.key3, msg=bytes(w, 'utf-8'), digestmod=SHA256).digest()
        return (Fw, Gw, Pw)

    def search(self, w):
        return self.database.search(self.srch_token(w))

    def encrypt(self, documents):
        # files = [{0:["keyord1","keyword2"]},{1: ["keyword1"]},{2:[...]},...]
        z = 2 #TODO

        # calculate total amount of keywords in all provided documents
        total_keywords_amounts = 0
        for _, keywords in documents:
            total_keywords_amounts += len(keywords)

        # initialize data structures
        search_array_length = (total_keywords_amounts + z)
        delete_array_length = (total_keywords_amounts + z)
        A_s = [None] * search_array_length # search array 
        A_d = [None] * delete_array_length # deletion array
        T_s = dict() # search table, maps keywords to the entry document in search array A_s
        T_d = dict() # delete table, maps documents to the keywords in it
        
        zeros = 0
        zeros = zeros.to_bytes(16,'big')


        for doc_id, doc_keywords  in documents:
            
            # DELETION
            Ff = HMAC.new(self.key1, msg=bytes(doc_id, 'utf-8'), digestmod=SHA256).digest()
            Gf = HMAC.new(self.key2, msg=bytes(doc_id, 'utf-8'), digestmod=SHA256).digest()
            Pf = HMAC.new(self.key3, msg=bytes(doc_id, 'utf-8'), digestmod=SHA256).digest()

            addr_d_D1 = zeros
            # END DELETION


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
                    temp = XOR(T_s[Fw], Gw)
                    # addr_s_N1 = addr_s_N1[16:] # Addr size is 16, so we do not need the first 16 leading zeros
                    addr_s_N1 = temp[:16]
                    # DELETION
                    addr_d_N1 = temp[-16:]
                    # END DELETION
                    myprint("Already exists an entry in the search table, namely", T_s[Fw])
                    myprint("Therefore we xor this with Gw", Gw, "to obtain ", addr_s_N1)
                else: # Else there is no document with this keyword yet, 
                    # so Addr_s(N+1)=Addr_d(N+1)=0 string as defined in the paper
                    addr_s_N1 = zeros
                    # DELETION
                    addr_d_N1 = zeros
                    # END DELETION
                    myprint("No entry in the search table exists")
                

                # DELETION 
                while True:
                    # temporary pointer, stable only at the end of the word loop
                    # i.e. when one document has been processed
                    addr_d_D = randrange(0, delete_array_length -1) 
                    if A_d[addr_d_D] == None:
                        break
                # END DELETION
                
                # Put into search table lookup
                # T_s[Fw] = XOR(addr_s_N.to_bytes(32,'big'), Gw)
                T_s[Fw] = XOR(addr_s_N.to_bytes(16,'big') + addr_d_D.to_bytes(16,'big'), Gw)
                myprint("Updated search table to ", T_s[Fw], "which is", addr_s_N, "XOR with", Gw)
                
                # Node for search array is ((id || addr(N+1)) ^H1, ri)
                Ni = (XOR(doc_id + addr_s_N1, H1), ri)

                myprint("The node stored in the search array looks like ", Ni)
                myprint("Which before encryption was", doc_id + addr_s_N1, "for doc_id", doc_id, "and address next address", addr_s_N1)
                
                # Store in search array
                A_s[addr_s_N] = Ni

                # 3
                # 3a
                # doesnt really make sense for delete
                """ if Ff in T_d:
                    addr_d_D1 = XOR(T_d[Ff], Gf)
                    addr_d_D1 = addr_d_D1[16:]
                else:
                    addr_d_D1 = zeros # Addr(D+1)=0 string """

                
                # addr_d_D1 = zeros # defined before the words loop
                addr_d_N_minus_1 = zeros
                # addr_d_N1 = zeros # zeroes if end
                # addr_s_N
                addr_s_minus_N1 = zeros
                # addr_s_N1 
                
                ri_prime = get_random_bytes(32)
                H2 = SHA256.new(Pf + ri_prime).digest()

                # print(len(addr_d_D1))
                # print(len(addr_d_N_minus_1)) # points at pos of dual D in A_d (prev)
                # print(len(addr_d_N1))
                # print(len(addr_s_N.to_bytes(16,'big')))
                # print(len(addr_s_minus_N1)) # points at pos of N in A_s (prev)
                # print(len(addr_s_N1))
                # print(len(Fw))
                # print(len(H2 * 4))
                
                Di = (XOR(addr_d_D1 + addr_d_N_minus_1 + addr_d_N1 + addr_s_N.to_bytes(16,'big') + addr_s_minus_N1 + addr_s_N1 + Fw, H2 * 4), ri_prime)
                A_d[addr_d_D] = Di

                if addr_d_N1 != zeros: # if there are no words to delete
                    previous_d, ri_prime = A_d[int.from_bytes(addr_d_N1, 'big')]

                    # homomorphically modify addresses
                    xorstring = zeros + addr_d_D.to_bytes(16,'big') + 2 * zeros + addr_s_N.to_bytes(16,'big') + zeros + 2 * zeros
                    previous_d = XOR(previous_d, xorstring)
                    A_d[int.from_bytes(addr_d_N1, 'big')] = previous_d, ri_prime
                
                addr_d_D1 = addr_d_D.to_bytes(16,'big') # temporary Td pointer

            # 3b
            T_d[Ff] = XOR(zeros + addr_d_D1, Gf) 

        
        # 4 create L_free list
        """ previous_free = zeros
        for i in range(z):
            
            while True:
                free = randrange(0, len(A_s))
                if A_s[free] is None:
                    break
            
            A_s[free] = (pad(previous_free, SHA256.block_size),  bytes(bytearray(32))) # TODO this does not include ID?
            previous_free = bytes(str(free), 'utf-8')
        
        T_s["free"] = pad(previous_free, SHA256.block_size) """

        

        # 5 fill remain A_s and A_d with random strings of length that fits in A_s
        """ for i in range(len(A_s)):
            if A_s[i] == None:
                A_s[i] = (get_random_bytes(int(math.ceil(math.log(len(A_s),10)))), get_random_bytes(int(math.ceil(math.log(len(A_s),10)))))
 """
        # 6 encrypt each document using AES
        # TODO leave this for now

        # 7
        # self.database.first_setup(A_s, T_s)
        self.database.first_setup(A_s, T_s, A_d, T_d)
        # return (A_s,T_s)
        return (A_s,T_s, A_d, T_d)



