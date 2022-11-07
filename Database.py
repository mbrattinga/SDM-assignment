import math
from Crypto.Hash import SHA256


class Database():

    def __init__(self) -> None:

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
        print("Starting search on database...")
        zeros = bytes("0" * int(math.ceil(math.log((len(self.A_s))))), 'utf-8')

        # Parse search token
        (tau_1, tau_2, tau_3) = search_token
        

        files = list()

        # Return empty list if tau1 not in search table
        if not tau_1 in self.T_s:
            return []

         # step 2
        # recover pointer to first node of list
        alpha_1 = bytes(a ^ b for a,b in zip(self.T_s[tau_1], tau_2))

        # step 3
        # look up N1
        while True:
            N_1 = self.A_s[alpha_1]
            (v_1, r_1) = N_1

            H1 = SHA256.new(tau_3 + r_1).digest()
            x = bytes(a ^ b for a,b in zip(v_1, H1)) # x = id_1 || 0 || addr_s_N+

            files.append(x) # TODO only append the id

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
        
