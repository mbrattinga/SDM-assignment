class Database():
    def __init__(self) -> None:

        # array(s) stored in the server
        # should be an array for each client (?)
        self.array = [bytes]


    def search(self, gamma, c, tau_s):
        """"
        gamma is the tuple (A_s, T_s, A_d, T_d) which is returned as encrypt() output
        c is (c1, c2, c3 ... cn) from step 6 of encrypt(), and is returned in encrypt() output
        t_s must be interpreted as tuple (t1, t2, t3)
        """

        # step 1
        # get t1 from t_s
        tau_1 = tau_s[0]
        tau_2 = tau_s[1]
        tau_3 = tau_s[2]

        a_s = gamma[0]
        t_s = gamma[1]
        a_d = gamma[2]
        t_d = gamma[3]


        # if t1 is not present in t_s
        if tau_1 is None:
            return []

        # step 2
        # recover pointer to first node of list
        # T_s comes from gamma


        alpha1, alpha1_p = xor_todo(t_s[tau_1], tau_2)

        # step 3
        # look up N1

        n = []
        n_decrypted = []
        id = []
        n.append( a_s[alpha1])

        # parse n_1 as


        n_decrypted.append(decr_todo(n[0], tau_3))
        v1, r1 = n[0]
        (id1, 0, addrs) = xor_todo( v1 ,hmac_fn(tau_3, r1))
        n.append(addrs)
        id.append(id1)

        # step 4
        # repeat step 3 until address in the tuple is zero
        # this gets all nodes for the search keyword
        while addrs != 0:
            n_decrypted.append(decr_todo(n[-1], tau_3))
            v1, r1 = n[-1]
            (id, 0, addrs) = xor_todo (v1, hmac_fn(tau_3, r1))
            n.append(addrs)
            id.append(id)

        # for all ids found, return the encrypted documents/locations
        c_filtered = [c[id_item] for id_item in id]

        return c_filtered





