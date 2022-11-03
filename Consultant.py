from Crypto.Random import get_random_bytes

class Consultant():
    def __init__(self, database , sec_param = 2 ** 6):
        self.sec_param = sec_param

        # generate master key
        self.master_key = get_random_bytes(sec_param)
        print("Master key:", self.master_key)

        # set database
        self.database = database
