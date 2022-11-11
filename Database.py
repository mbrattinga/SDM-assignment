import math
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Util import XOR, myprint

class Database():
    def __init__(self) -> None:
        self.A_s = list()
        self.T_s = dict()
        self.initialized = False

    def first_setup(self, A_s, T_s):
        """Sets up the search array and search table, which is required the first time the database is accessed.

        Args:
            A_s ([(byte, byte)]): search array
            T_s (_type_): search table

        Raises:
            Exception: if the database has been set-up before, as this only should be done once.
        """
        if not self.initialized:
            self.A_s = A_s
            self.T_s = T_s
            self.initialized = True
        else:
            raise Exception("The database has been set-up before, cannot do that twice!")


    def add(self, add_token):
        """Adds a document entry to the database based on the given add token

        Args:
            add_token ([bytes]): add token that has to be added to the database

        Raises:
            Exception: if the database has not been set-up using `first_setup()` before, which is required

        Returns:
            bool: True if the document is sucesfully added
        """

        if not self.initialized:
            raise Exception("The database has not been set-up before, please do so first!")

        zeros = bytearray(16)
        # 2. for each add token (each keyword)
        for lambda_i in add_token:
            # parse lambda
            Fw, Gw, A_s_node, ri = lambda_i[:32], lambda_i[32:64], lambda_i[64:96], lambda_i[96:]

            # 2a. find last free location
            phi = int.from_bytes(self.T_s["free"], 'big')

            # 2b. update search table to second-to-last free
            self.T_s["free"] = self.A_s[phi][0]

            # 2c. recover pointer to first node with this keyword
            if Fw in self.T_s:
                alpha_1 = XOR(self.T_s[Fw], Gw) # decrypt to obtain address of first node for this word
                alpha_1 = alpha_1[16:] # we want 16 bytes, so remove leading zeros
            else: # there does not exist a node for this keyword yet
                alpha_1 = zeros
            
            # 2d. store node on the free location in the search array
            self.A_s[phi] = (XOR(A_s_node, (zeros + alpha_1)),ri)

            # 2e. update search table
            self.T_s[Fw] = XOR(phi.to_bytes(32, 'big'), Gw)
            
            return True
        return False

    def search(self, search_token):
        """Returns the documents in the database for the given search token

        Args:
            search_token ((bytes,bytes,bytes)): search token that represents the search query

        Raises:
            Exception: if the database has not been set-up using `first_setup()` before, which is required

        Returns:
            [str]: list of document identifiers that match the given search token
        """

        if not self.initialized:
            raise Exception("The database has not been set-up before, please do so first!")

        # 1. parse search token
        (tau_1, tau_2, tau_3) = search_token
        

        files = list()
        # 1. return empty list if tau1 not in search table
        if not tau_1 in self.T_s:
            return []

        # 2. recover pointer to first node of list
        alpha_1 = int.from_bytes(XOR(self.T_s[tau_1], tau_2), 'big')

        # 3. lookup the first node and decrypt to obtain the next node in the linked list
        # 4. continue until you are at the end
        address_lookup = alpha_1
        while True:
            # get and parse the node
            N_1 = self.A_s[address_lookup]
            (v_1, r_1) = N_1

            # decrypt the node
            H1 = SHA256.new(tau_3 + r_1).digest()
            x = XOR(v_1, H1)

            # parse the decrypted node
            id, addr_s_N1 = x[:16], x[16:]

            # add document identifier to result list
            files.append(id)

            # determine whether there is a next node or not (address is zero bytes)
            if addr_s_N1 == bytes("0" * 16, 'utf-8') or addr_s_N1 == bytearray(16): # bit hacky, either 0000 bytes or string 0000
                break
            else:
                # save the address of the next node for the next iteration
                address_lookup = int.from_bytes(addr_s_N1, 'big')
        return files
        
