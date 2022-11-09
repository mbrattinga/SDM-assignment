import math
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Util import XOR, myprint

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

    def add(self, add_token):
        print("Starting adding on database")
        zeros = bytes("0" * 16, 'utf-8')

        for lambda_i in add_token:
            Fw, Gw, A_s_node, ri = lambda_i[:32], lambda_i[32:64], lambda_i[64:96], lambda_i[96:]

            phi = int(unpad(self.T_s["free"], SHA256.block_size)) # find last free location
            myprint("Phi is", phi)

            self.T_s["free"] = pad(self.A_s[phi][0], SHA256.block_size) # update search table to previous free entry
            myprint("New free entry: ", self.T_s["free"])

            # check if there already is a node for this keyword
            if Fw in self.T_s:
                alpha_1 = XOR(self.T_s[Fw], Gw) # decrypt 
            else: # there does not exist a node for this keyword yet
                alpha_1 = zeros * 2 # we need 32 bytes zeros for this
            
            # update the previous free node with the node we add
            self.A_s[phi] = (XOR(A_s_node, alpha_1),ri)

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
        alpha_1 = int.from_bytes(XOR(self.T_s[tau_1], tau_2), 'big')

        myprint("Adress in search table points to ", alpha_1)


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
            myprint("Checking next address for equality", addr_s_N1, bytes("0" * 16, 'utf-8'), addr_s_N1 == bytes("0" * 16, 'utf-8'), addr_s_N1 == bytearray(16))
            if addr_s_N1 == bytes("0" * 16, 'utf-8') or addr_s_N1 == bytearray(16): # bit hacky, either 0000 bytes or string 0000
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
        
