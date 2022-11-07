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
        (Fw, Gw, Pw) = search_token
        print("Starting search on database...")