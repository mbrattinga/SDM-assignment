from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

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

    def first_setup(self, A_s, T_s):
        if not self.initialized:
            self.A_s = A_s
            self.T_s = T_s
        else:
            raise Exception("The database has been set-up before, cannot do that twice!")

    def search(self, search_token):
        (Fw, Gw, Pw) = search_token
        print("Starting search on database...")


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