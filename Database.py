import math
from Crypto.Hash import SHA256
from Util import XOR, myprint

class Database():

    def __init__(self) -> None:

        # array(s) stored in the server
        self.A_s = [] # * (total_keywords_amounts + z) # search array 
        self.A_d = [] # * (total_keywords_amounts + z) # deletion array
        self.T_s = dict() # search table, maps (enc) keywords to the entry document in search array A_s
        self.T_d = dict() # deletion table, maps documents to the entry position in deletion array A_d

        self.free = "asdasdasd"

        H1, H2 = SHA256.new(), SHA256.new()

        # # array(s) stored in the server
        # # should be an array for each client (?)
        # self.A_s = [bytes]
        self.A_s = list()
        self.T_s = dict()
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
            if addr_s_N1 == bytes("0" * 16, 'utf-8'):
                myprint("No more documents for this search query")
                break
            else:
                address_lookup = int.from_bytes(addr_s_N1, 'big')

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
        token1, token2, token3, doc_id = delete_token

        T_d = [] # to be removed
        if token1 not in T_d:
            return

        # 2 
        # find the first node of L_f
        alfa_1_prime = T_d[token1] ^ token2 # position first node

        # 3
        f = [] # to be removed
        for i in range(1, len(f) + 1): # for each unique keywords in f

            # a
            # decrypt D_i
            D_i, r = self.A_d[alfa_1_prime]
            alfa1, alfa2, alfa3, alfa4, alfa5, alfa6, mu = D[i] ^ self.H2.update(token3 + r)

            # b
            # delete D_i (replace with random)
            self.A_d[alfa_1_prime] = get_random_bytes(128) # 128 should be the sec param

            # c
            # address of last free node
            gamma, zero = self.T_s[free] # zero TODO

            # d
            # free entry in the search table point to D_i’s dual
            self.T_s[free] = alfa4, zero

            # e
            # free location of D_i’s dual
            self.A_s[alfa4]  = gamma, alfa_1_prime

            # f
            # node that precedes D_i’s dual
            # N_minus1 = something # TODO

            # Update N−1’s “next pointer”
            # beta1 = id
            # beta2 = address
            # r_minus1 = randomness
            beta1, beta2, r_minus1 = self.A_s[alfa5]
            self.A_s[alfa5] = beta1, beta2 ^ alfa4 ^ alfa6, r_minus1

            # update the pointers of N−1’s dual
            # beta1 = address_d(D+1)
            # beta2 = address_d(N-1)
            # beta3 = address_d(N+1)
            # beta4 = address_s(N)
            # beta5 = address_s(N-1)
            # beta6 = address_s(N+1)
            # mu_star = F_key1(w)
            # r_star_minus1 = randomness
            beta1, beta2, beta3, beta4, beta5, beta6, mu_star, r_star_minus1 = self.A_s[alfa2]
            self.A_s[alfa2] = beta1, beta2, beta3 ^ alfa_1_prime ^ alfa3, beta4, beta5, beta6 ^ alfa4 ^ alfa6, mu_star, r_star_minus1

            # g
            # node that follows D_i’s dual
            # N_plus1 = something # TODO

            # Update N+1’s dual
            beta1, beta2, beta3, beta4, beta5, beta6, mu_star, r_star_plus1 = self.A_s[alfa3]
            self.A_s[alfa3] = beta1, beta2 ^ alfa_1_prime ^ alfa2, beta3, beta4, beta5 ^ alfa4 ^ alfa5, beta6, mu_star, r_star_plus1

            # h
            alfa_1_prime = alfa1

        # 4
        # we don't have the ciphertexts yet

        # 5
        del self.T_d[t1]