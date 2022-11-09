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
print("client_a search cow, should not yield results:", client_a.search("cow"))
print("client_a search dog, should yield 1 result:", client_a.search("dog"))
print("client_a search cat, should yield 2 results:", client_a.search("cat"))
print("consultant search dog for client_a, should yield 1 result:", consultant.search("dog", client_a.get_id()))
print()
print("client_a adds document with cow:", client_a.add(("myfile",["cow"])))
print("client_a searches cow again, now should yield 1 result:", client_a.search("cow"))
print()
print("client_b searches dog, should not yield results:", client_b.search("dog"))
print("consultant search dog for client_b, should not yield results:", consultant.search("dog", client_b.get_id()))
print("client_b adds document with dog:", client_b.add(("invoice33",["dog"])))
print("client_b searches dog, should yield 1 result:", client_b.search("dog"))
print("consultant search dog for client_b again, should yield in 1 result:", consultant.search("dog", client_b.get_id()))