from ast import keyword
from Database import Database
from Consultant import Consultant
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes, randrange
from Crypto.Util.Padding import pad

class Client():

    def __init__(self, id : int, consultant : Consultant, database : Database) -> None:
        self.id = id
        self.consultant = consultant
        self.database = database

        self.key = self.consultant.key_gen(self.id)

        # client's lookup table 
        # { keyword : list of document id containing that keyword }
        self.lookup_table = {}

        # TODO the paper users k1,2,3 for these F,G,P hmacs
    
    def get_id(self) -> int:
        """ Function to retrieve the id of the client
        Returns:
            int: the client id
        """
        return self.id

    # TODO replace all ^ xor operations by correct ones
    def encrypt(self, documents):
        # files = [{0,["keyord1","keyword2"]},{1, ["keyword1"]},{2,[...]},...]
        z = 10000

        # calculate total amount of keywords in all provided documents
        total_keywords_amounts = 0
        for (_, keywords) in documents:
            initial_size += len(keyword)

        # initialize data structures
        A_s = [] * (total_keywords_amounts + z) # search array 
        # A_d = [] * (total_keywords_amounts + z) # deletion array
        T_s = dict() # search table, maps keywords to the entry document in search array A_s
        # T_d = dict() # deletion table, maps documents to the entry position in deletion array A_d

        # Check which document contains keyword w_i for each possible keyword, as defined by the TTP
        for i, w in enumerate(Consultant.ALLOWED_KEYWORDS): 
            Fw = HMAC.new(self.key, msg=w, digestmod=SHA256).hexdigest()
            Gw = HMAC.new(self.key, msg=w, digestmod=SHA256).hexdigest()
            Pw = HMAC.new(self.key, msg=w, digestmod=SHA256).hexdigest()
            for ii, (doc_id, doc_keywords) in enumerate(documents):
                if w in doc_keywords:
                    # find random address in A_s that is not used yet
                    while True:
                        A_s_address = randrange(len(A_s))
                        if A_s[A_s_address] is None:
                            break
                    # # find random address in A_d that is not used yet
                    # while True:
                    #     A_d_address = randrange(len(A_d))
                    #     if A_d[A_d_address] is None:
                    #         break

                    # (2a) calculate Ni and store in search array
                    ri = get_random_bytes(self.consultant.SECURITY_PARAMETER)
                    addr_s_Nplus = 0 # TODO how can we possibly now this one already?
                    H1 = SHA256.new(Pw + ri)
                    Ni = ((doc_id + pad(addr_s_Nplus)) ^ H1) + ri
                    A_s[A_s_address] = Ni

                    # (2b)
                    T_s[Fw] = (A_s_address) ^ Gw #  + A_d_address
        
        # 4
        

        # 5

        # 6

        # 7



