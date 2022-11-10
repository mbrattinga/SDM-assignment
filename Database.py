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

    def add(self, add_token : list()):
        myprint("Starting adding on database")
        zeros = bytearray(16)

        tau1_Ff = add_token.pop(0)
        tau2_Gf = add_token.pop(0)

        phi_star_minus_1 = zeros

        # 2
        for lambda_i in add_token:
            # Fw, Gw, A_s_node, ri = lambda_i[:32], lambda_i[32:64], lambda_i[64:96], lambda_i[96:]
            Fw, Gw, A_s_node, ri = lambda_i[:32], lambda_i[32:64], lambda_i[64:96], lambda_i[96:128]
            A_d_node, ri_prime = lambda_i[128:256], lambda_i[256:]
            myprint("Search table free is: ", self.T_s["free"])

            # a
            # phi = int(unpad(self.T_s["free"], SHA256.block_size)) # find last free location
            # phi = free location in A_s pointed by A_s['free']
            phi = int.from_bytes(self.T_s["free"], 'big')
            myprint("Phi is", phi)

            # phi_minus_1, phi_star_random
            phi_minus_1, phi_star_random = self.A_s[phi]

            # b
            # self.T_s["free"] = pad(self.A_s[phi][0], SHA256.block_size) # update search table to previous free entry
            # self.T_s["free"] = self.A_s[phi][0] # update search table to point to previous free entry
            self.T_s["free"] = zeros + phi_minus_1
            # self.T_s["free"] = phi_minus_1 + zeros
            myprint("New free entry: ", self.T_s["free"])

            # c
            # check if there already is a node for this keyword
            if Fw in self.T_s:
                alpha = XOR(self.T_s[Fw], Gw) # decrypt to obtain address of first node for this word
                alpha_1 = alpha[:16] 
                alpha_1_star = alpha[16:] 
            else: # there does not exist a node for this keyword yet
                alpha_1 = zeros
                alpha_1_star = zeros
            
            # d
            # insert new node in the search array (on the spot which we found to be free earlier on)
            self.A_s[phi] = XOR(A_s_node, zeros + alpha_1), ri

            # e
            # update search table
            # phi_star_random should just be a bytearray of zeros
            self.T_s[Fw] = XOR(phi.to_bytes(16, 'big') + phi_star_random[-16:], Gw)


            # DELETE NOT STABLE
            # f
            if alpha_1_star != zeros:
                D1, r = self.A_d[int.from_bytes(alpha_1_star, 'big')]
                self.A_d[int.from_bytes(alpha_1_star, 'big')] = XOR(D1, zeros + phi_star_random + 2 * zeros + phi.to_bytes(16, 'big') + 2 * zeros), r

            # g
            self.A_d[int.from_bytes(phi_star_random, 'big')] = XOR(A_d_node, phi_star_minus_1 + zeros + alpha_1_star + phi.to_bytes(16, 'big') + zeros + alpha_1 + Fw), ri_prime
            phi_star_minus_1 = phi_star_random

            """ # h
            if lambda_i == add_token[0]:
                self.T_d[tau1_Ff] = XOR(phi_star_random + zeros, tau2_Gf) """

        # h
        self.T_d[tau1_Ff] = XOR(phi_star_minus_1, tau2_Gf)
             
        return True

            



        return False

    def search(self, search_token):
        myprint("Starting search on database...")

        # Parse search token
        (tau_1_Fw, tau_2_Gw, tau_3_Pw) = search_token
        

        files = list()

        # Return empty list if tau1 not in search table
        if not tau_1_Fw in self.T_s:
            myprint("Could not find a result for this search...")
            return []

        # step 2
        # recover pointer to first node of list
        alpha_1_addr_s_N = int.from_bytes(XOR(self.T_s[tau_1_Fw], tau_2_Gw)[:16], 'big')
        alpha_1_prime_addr_d_D = int.from_bytes(XOR(self.T_s[tau_1_Fw], tau_2_Gw)[16:], 'big')
        

        myprint("Address in search table points to ", alpha_1_addr_s_N)


        # step 3
        # look up N1
        address_lookup = alpha_1_addr_s_N

        while address_lookup != 0:
            v_1, r_1 = self.A_s[address_lookup]
            myprint("The node at that address looks like ", self.A_s[address_lookup])

            H1 = SHA256.new(tau_3_Pw + r_1).digest()
            x = XOR(v_1, H1)
            myprint("And the decryption of that node looks like ", x)

            id, addr_s_N1 = x[:16], x[16:]
            myprint("Thus the id of this document is", id, "and the next address is ", addr_s_N1)

            files.append(id)

            address_lookup = int.from_bytes(addr_s_N1, 'big')

        """ while True:
            N_1 = self.A_s[address_lookup]
            myprint("The node at that address looks like ", N_1)
            (v_1, r_1) = N_1

            H1 = SHA256.new(tau_3_Pw + r_1).digest()
            x = XOR(v_1, H1)
            myprint("And the decryption of that node looks like ", x)

            id, addr_s_N1 = x[:16], x[16:]
            myprint("Thus the id of this document is", id, "and the next address is ", addr_s_N1)

            files.append(id)
            # if addr_s_N1.decode('utf-8') == "0" * 16:
            # if addr_s_N1 == bytes("0" * 16, 'utf-8'):
            if addr_s_N1 == bytearray(16):
            # if address_lookup == 0:
                myprint("No more documents for this search query")
                break
            else:
                address_lookup = int.from_bytes(addr_s_N1, 'big')
                myprint("The next address to lookup ", addr_s_N1, "is integer ", address_lookup) """

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
        token1_Ff, token2_Gf, token3_Pf, doc = delete_token
        _doc_id, keywords = doc

        if token1_Ff not in self.T_d:
            print(f"The document {_doc_id} is not in the database (ask the consultant)")
            return

        print(f"Deleting {doc}")

        # 2 
        # find the first node of L_f
        # 32B
        alfa_1_prime_addr_first_node_Ad = XOR(self.T_d[token1_Ff], token2_Gf) # position first node in A_d

        # 3
        # for i in range(1, len(keywords) + 1): # for each unique keywords in f
        for _ in range(len(keywords)): # for each unique keywords in f

            # a
            # decrypt D_i
            D_i, r = self.A_d[int.from_bytes(alfa_1_prime_addr_first_node_Ad, 'big')]
            H2 = self.H2.new(token3_Pf + r).digest()
            D_i = XOR(D_i, H2 * 4)
            alfa1_addr_d_D1 = D_i[:16] # address_d(D1)
            alfa2_addr_d_N_1 = D_i[16:32] # address_d(N-1)
            alfa3_addr_d_N1 = D_i[32:48] # address_d(N+1)
            alfa4_addr_s_N = D_i[48:64] # address_s(N)
            alfa5_addr_s_N_1 = D_i[64:80] # address_s(N-1)
            alfa6_addr_s_N1 = D_i[80:96] # address_s(N+1)
            mu_Fw = D_i[96:] # Fw

            # b
            # delete D_i (replace with random) # TODO lengths
            """ self.A_d[int.from_bytes(alfa_1_prime, 'big')] = \
                get_random_bytes(len(self.A_d[int.from_bytes(alfa_1_prime, 'big')][0])), \
                get_random_bytes(len(self.A_d[int.from_bytes(alfa_1_prime, 'big')][1])) """
            self.A_d[int.from_bytes(alfa_1_prime_addr_first_node_Ad, 'big')] = b'emptied', b'emptied' # TODO Remove
                # 128 should be the sec param

            # c
            # gamma: address of last free node in A_s
            # gamma, zeros = self.T_s["free"] 
            gamma_addr_free_node_in_As = self.T_s["free"] 

            # d
            # free entry in the search table point to D_i’s dual | # alfa4 = address_s(N)
            # self.T_s["free"] = bytearray(16) + alfa4, zeros
            self.T_s["free"] = bytearray(16) + alfa4_addr_s_N

            # e
            # free location of D_i’s dual (i.e., N_i)
            if len(alfa_1_prime_addr_first_node_Ad) != 32:
                alfa_1_prime_addr_first_node_Ad = bytearray(16) + alfa_1_prime_addr_first_node_Ad
            self.A_s[int.from_bytes(alfa4_addr_s_N, 'big')] = gamma_addr_free_node_in_As, alfa_1_prime_addr_first_node_Ad # gamma = addr next free node | alfa_1_prime is its dual

            # f (boekkeeping logic?)
            # node that precedes D_i’s dual
            # N_minus1 = alfa5 #TODO?

            # Update N−1’s “next pointer” | alfa5 = address_s(N-1)
            if alfa5_addr_s_N_1 == bytearray(16): # first element in the T_s list

                # if only element
                if alfa6_addr_s_N1 == bytearray(16):
                    del self.T_s[mu_Fw] # delete entry for that word
                else:
                    # homomorphically modify address of T_s[Fw] (alfa4, alfa5) A_s, (alfa_1_prime, alfa3) A_sd
                    self.T_s[mu_Fw] = XOR(self.T_s[mu_Fw], XOR(alfa4_addr_s_N, alfa6_addr_s_N1) + XOR(alfa_1_prime_addr_first_node_Ad, alfa3_addr_d_N1))
            else:
                # update pointer of N-1 in A_s | alfa5 = address_s(N-1)
                beta1_beta2, r_minus1 = self.A_s[int.from_bytes(alfa5_addr_s_N_1, 'big')]
                beta1 = beta1_beta2[:16] # doc_id
                beta2 = beta1_beta2[16:32] # next address of the same word in A_s
                self.A_s[int.from_bytes(alfa5_addr_s_N_1, 'big')] = beta1 + XOR(XOR(beta2, alfa4_addr_s_N), alfa6_addr_s_N1), r_minus1

                # update the pointers of N−1’s dual | alfa2 = address_d(N-1)
                # r_star_minus1 = randomness
                tmp, r_star_minus1 = self.A_d[int.from_bytes(alfa2_addr_d_N_1, 'big')]
                beta1_addr_d_D1 = tmp[:16] # addr_d_D1
                beta2_addr_d_N_1 = tmp[16:32] # addr_d_N_minus_1
                beta3_addr_d_N1 = tmp[32:48] # addr_d_N_plus_1
                beta4_addr_s_N = tmp[48:64] # addr_s_N.to_bytes(16,'big')
                beta5_addr_s_N_1 = tmp[64:80] # addr_s_N_minus_1
                beta6_addr_s_N1 = tmp[80:96] # addr_s_N_plus_1
                mu_star_Fw = tmp[96:128] # Fw
                self.A_d[int.from_bytes(alfa2_addr_d_N_1, 'big')] = beta1_addr_d_D1 + beta2_addr_d_N_1 + XOR(XOR(beta3_addr_d_N1, alfa_1_prime_addr_first_node_Ad[-16:]), alfa3_addr_d_N1) + beta4_addr_s_N + beta5_addr_s_N_1 + XOR(XOR(beta6_addr_s_N1, alfa4_addr_s_N), alfa6_addr_s_N1) + mu_star_Fw, r_star_minus1

            # g
            # node that follows D_i’s dual
            # N_plus1 = something # TODO?

            # Update N+1’s dual | alfa3 = address_d(N+1)
            if alfa3_addr_d_N1 != bytearray(16):
                tmp, r_star_plus1 = self.A_d[int.from_bytes(alfa3_addr_d_N1, 'big')]
                beta1_addr_d_D1 = tmp[:16] # addr_d_D1
                beta2_addr_d_N_1 = tmp[16:32] # addr_d_N_minus_1
                beta3_addr_d_N1 = tmp[32:48] # addr_d_N_plus_1
                beta4_addr_s_N = tmp[48:64] # addr_s_N.to_bytes(16,'big')
                beta5_addr_s_N_1 = tmp[64:80] # addr_s_minus_N1
                beta6_addr_s_N1 = tmp[80:96] # addr_s_N1
                mu_star_Fw = tmp[96:128] # Fw
                self.A_d[int.from_bytes(alfa3_addr_d_N1, 'big')] = beta1_addr_d_D1 + XOR(XOR(beta2_addr_d_N_1, alfa_1_prime_addr_first_node_Ad[-16:]), alfa2_addr_d_N_1) + beta3_addr_d_N1 + beta4_addr_s_N + XOR(XOR(beta5_addr_s_N_1, alfa4_addr_s_N), alfa5_addr_s_N_1) + beta6_addr_s_N1 + mu_star_Fw, r_star_plus1

            # h
            alfa_1_prime_addr_first_node_Ad = alfa1_addr_d_D1

        # 4
        # we don't have the ciphertexts yet

        # 5
        del self.T_d[token1_Ff]