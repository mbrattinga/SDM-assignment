from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(database)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)


files = [("0", ["cat","dog"]),("1", ["cat"])]
(A_s, T_s) = client_a.encrypt(files)
print()
print()
print()
print()
print()
print("client search asdf result:", client_a.search("asdf"))
print("client search dog result:", client_a.search("dog"))
print("client search cat result:", client_a.search("cat"))
print("consultant search dog result:", consultant.search("dog", client_a.get_id()))