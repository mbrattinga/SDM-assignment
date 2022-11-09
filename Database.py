import math
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Util import XOR, myprint
from Crypto.Random import get_random_bytes

class Database():

    def __init__(self) -> None:

        # array(s) stored in the server
        # # should be an array for each client (?)
        self.A_s = [] # * (total_keywords_amounts + z) # search array 
        self.A_d = [] # * (total_keywords_amounts + z) # deletion array
        self.T_s = dict() # search table, maps (enc) keywords to the entry document in search array A_s
        self.T_d = dict() # deletion table, maps documents to the entry position in deletion array A_d

        # self.free = "asdasdasd"

        self.H1, self.H2 = SHA256.new(), SHA256.new()

        self.initialized = False

    # def first_setup(self, A_s, T_s):
    def first_setup(self, A_s, T_s, A_d, T_d):
        if not self.initialized:
            self.A_s = A_s
            self.T_s = T_s
            self.A_d = A_d
            self.T_d = T_d
        else:
            raise Exception("The database has been set-up before, cannot do that twice!")

    def add(self, add_token):
        myprint("Starting adding on database")
        zeros = bytearray(16)

        # 2
        for lambda_i in add_token:
            Fw, Gw, A_s_node, ri = lambda_i[:32], lambda_i[32:64], lambda_i[64:96], lambda_i[96:]
            myprint("Search table free is: ", self.T_s["free"])

            # a
            # phi = int(unpad(self.T_s["free"], SHA256.block_size)) # find last free location
            phi = int.from_bytes(self.T_s["free"], 'big')
            myprint("Phi is", phi)

            # b
            # self.T_s["free"] = pad(self.A_s[phi][0], SHA256.block_size) # update search table to previous free entry
            self.T_s["free"] = self.A_s[phi][0] # update search table to point to previous free entry
            myprint("New free entry: ", self.T_s["free"])

            # c
            # check if there already is a node for this keyword
            if Fw in self.T_s:
                alpha_1 = XOR(self.T_s[Fw], Gw) # decrypt to obtain address of first node for this word
                alpha_1 = alpha_1[16:] # we want 16 bytes, so remove leading zeros
            else: # there does not exist a node for this keyword yet
                alpha_1 = zeros
            
            # d
            # insert new node in the search array (on the spot which we found to be free earlier on)
            self.A_s[phi] = (XOR(A_s_node, (zeros + alpha_1)),ri)

            # e
            # update search table
            self.T_s[Fw] = XOR(phi.to_bytes(32, 'big'), Gw)
            
            return True

            



        return False

    def search(self, search_token):
        myprint("Starting search on database...")

        # Parse search token
        (tau_1, tau_2, tau_3) = search_token
        

        files = list()

        # Return empty list if tau1 not in search table
        if not tau_1 in self.T_s:
            myprint("Could not find a result for this search...")
            return []

        # step 2
        # recover pointer to first node of list
        alpha_1 = int.from_bytes(XOR(self.T_s[tau_1], tau_2)[:16], 'big')
        alpha_1_prime = int.from_bytes(XOR(self.T_s[tau_1], tau_2)[16:], 'big')
        

        myprint("Address in search table points to ", alpha_1)


        # step 3
        # look up N1
        address_lookup = alpha_1
        while True:
            N_1 = self.A_s[address_lookup]
            myprint("The node at that address looks like ", N_1)
            (v_1, r_1) = N_1

            H1 = SHA256.new(tau_3 + r_1).digest()
            x = XOR(v_1, H1)
            myprint("And the decryption of that node looks like ", x)

            id, addr_s_N1 = x[:16], x[16:]
            myprint("Thus the id of this document is", id, "and the next address is ", addr_s_N1)

            files.append(id)
            # if addr_s_N1.decode('utf-8') == "0" * 16:
            # if addr_s_N1 == bytes("0" * 16, 'utf-8'):
            zeros = bytearray(16)
            if addr_s_N1 == zeros:
                myprint("No more documents for this search query")
                break
            else:
                address_lookup = int.from_bytes(addr_s_N1, 'big')
                myprint("The next address to lookup ", addr_s_N1, "is integer ", address_lookup)

        return files





        # # step 4
        # # repeat step 3 until address in the tuple is zero
        # # this gets all nodes for the search keyword
        # while addrs != 0:
        #     n_decrypted.append(decr_todo(n[-1], tau_3))
        #     v1, r1 = n[-1]
        #     (id, 0, addrs) = xor_todo (v1, hmac_fn(tau_3, r1))
        #     n.append(addrs)
        #     id.append(id)

        # # for all ids found, return the encrypted documents/locations
        # c_filtered = [c[id_item] for id_item in id]

        # return c_filtered



    # def delete(index, ctxt, delete_token):
    def delete(self, delete_token):
        
        # 1
        token1, token2, token3, doc = delete_token
        _doc_id, keywords = doc

        if token1 not in self.T_d:
            return

        # 2 
        # find the first node of L_f
        # 32B
        alfa_1_prime = XOR(self.T_d[token1], token2) # position first node in A_d

        # 3
        # for i in range(1, len(keywords) + 1): # for each unique keywords in f
        for _ in range(len(keywords)): # for each unique keywords in f

            # a
            # decrypt D_i
            D_i, r = self.A_d[int.from_bytes(alfa_1_prime, 'big')]
            H2 = self.H2.new(token3 + r).digest()
            D_i = XOR(D_i, H2 * 4)
            alfa1 = D_i[:16] # address_d(D1)
            alfa2 = D_i[16:32] # address_d(N-1)
            alfa3 = D_i[32:48] # address_d(N+1)
            alfa4 = D_i[48:64] # address_s(N)
            alfa5 = D_i[64:80] # address_s(N-1)
            alfa6 = D_i[80:96] # address_s(N+1)
            mu = D_i[96:] # Fw

            # b
            # delete D_i (replace with random) # TODO lengths
            """ self.A_d[int.from_bytes(alfa_1_prime, 'big')] = \
                get_random_bytes(len(self.A_d[int.from_bytes(alfa_1_prime, 'big')][0])), \
                get_random_bytes(len(self.A_d[int.from_bytes(alfa_1_prime, 'big')][1])) """
            self.A_d[int.from_bytes(alfa_1_prime, 'big')] = b'emptied', b'emptied' # TODO Remove
                # 128 should be the sec param

            # c
            # gamma: address of last free node in A_s
            # gamma, zeros = self.T_s["free"] 
            gamma = self.T_s["free"] 

            # d
            # free entry in the search table point to D_i’s dual | # alfa4 = address_s(N)
            # self.T_s["free"] = bytearray(16) + alfa4, zeros
            self.T_s["free"] = bytearray(16) + alfa4

            # e
            # free location of D_i’s dual (i.e., N_i)
            if len(alfa_1_prime) != 32:
                alfa_1_prime = bytearray(16) + alfa_1_prime
            self.A_s[int.from_bytes(alfa4, 'big')] = gamma, alfa_1_prime # gamma = addr next free node | alfa_1_prime is its dual

            # f (boekkeeping logic?)
            # node that precedes D_i’s dual
            # N_minus1 = alfa5 #TODO?

            # Update N−1’s “next pointer” | alfa5 = address_s(N-1)
            if alfa5 == bytearray(16): # first element in the T_s list

                # if only element
                if alfa6 == bytearray(16):
                    del self.T_s[mu] # delete entry for that word
                else:
                    # homomorphically modify address of T_s[Fw] (alfa4, alfa5) A_s, (alfa_1_prime, alfa3) A_sd
                    self.T_s[mu] = XOR(self.T_s[mu], XOR(alfa4, alfa6) + XOR(alfa_1_prime, alfa3))
            else:
                # update pointer of N-1 in A_s | alfa5 = address_s(N-1)
                beta1_beta2, r_minus1 = self.A_s[int.from_bytes(alfa5, 'big')]
                beta1 = beta1_beta2[:16] # id
                beta2 = beta1_beta2[16:32] # address
                self.A_s[int.from_bytes(alfa5, 'big')] = beta1 + XOR(XOR(beta2, alfa4), alfa6), r_minus1

                # update the pointers of N−1’s dual | alfa2 = address_d(N-1)
                # r_star_minus1 = randomness
                tmp, r_star_minus1 = self.A_d[int.from_bytes(alfa2, 'big')]
                beta1 = tmp[:16] # addr_d_D1
                beta2 = tmp[16:32] # addr_d_N_minus_1
                beta3 = tmp[32:48] # addr_d_N_plus_1
                beta4 = tmp[48:64] # addr_s_N.to_bytes(16,'big')
                beta5 = tmp[64:80] # addr_s_minus_N1
                beta6 = tmp[80:96] # addr_s_N1
                mu_star = tmp[96:128] # Fw
                self.A_d[int.from_bytes(alfa2, 'big')] = beta1 + beta2 + XOR(XOR(beta3, alfa_1_prime[-16:]), alfa3) + beta4 + beta5 + XOR(XOR(beta6, alfa4), alfa6) + mu_star, r_star_minus1

            # g
            # node that follows D_i’s dual
            # N_plus1 = something # TODO?

            # Update N+1’s dual | alfa3 = address_d(N+1)
            if alfa3 != bytearray(16):
                tmp, r_star_plus1 = self.A_d[int.from_bytes(alfa3, 'big')]
                beta1 = tmp[:16] # addr_d_D1
                beta2 = tmp[16:32] # addr_d_N_minus_1
                beta3 = tmp[32:48] # addr_d_N_plus_1
                beta4 = tmp[48:64] # addr_s_N.to_bytes(16,'big')
                beta5 = tmp[64:80] # addr_s_minus_N1
                beta6 = tmp[80:96] # addr_s_N1
                mu_star = tmp[96:128] # Fw
                self.A_d[int.from_bytes(alfa3, 'big')] = beta1 + XOR(XOR(beta2, alfa_1_prime[-16:]), alfa2) + beta3 + beta4 + XOR(XOR(beta5, alfa4), alfa5) + beta6 + mu_star, r_star_plus1

            # h
            alfa_1_prime = alfa1

        # 4
        # we don't have the ciphertexts yet

        # 5
        del self.T_d[token1]