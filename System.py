from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(database)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)


files = [("0", ["cat"]),("1", ["cat", "dog", "cow"]), ("2", ["cat", "cow"])]
# files = [("0", ["cat", "cow"])]
# (A_s, T_s) = client_a.encrypt(files)
(A_s, T_s, A_d, T_d) = client_a.encrypt(files)
print()
print("client_a searches cow:", client_a.search("cow"))
print("client_a searches dog:", client_a.search("dog"))
print("client_a searches cat:", client_a.search("cat"))
# delete not working yet! TODO
client_a.delete(("0", ["cat"]))
print("search cat after deleting document 0", client_a.search("cat"))
print("search dog after deleting document 0", client_a.search("dog"))
print("search cow after deleting document 0", client_a.search("cow"))

client_a.delete(("1", ["cat", "dog", "cow"]))
print("search cat after deleting document 1", client_a.search("cat"))
print("search dog after deleting document 1", client_a.search("dog"))
print("search cow after deleting document 1", client_a.search("cow"))

client_a.delete(("2", ["cat", "cow"]))
print("search cat after deleting document 2", client_a.search("cat"))
print("search dog after deleting document 2", client_a.search("dog"))
print("search cow after deleting document 2", client_a.search("cow"))

""" print("consultant search dog for client_a, should yield 1 result:", consultant.search("dog", client_a.get_id()))
print()
print("client_a adds document with cow:", client_a.add(("myfile",["cow"])))
print("client_a searches cow again, now should yield 1 result:", client_a.search("cow"))
print("consultant adds document with cow for client_a:", consultant.add(("myinvoice",["cow"]), client_a.get_id()))
print("client_a searches cow again, now should yield 2 results:", client_a.search("cow"))
print("consultant searches cow for client_a, now should yield 2 result:", consultant.search("cow", client_a.get_id()))
print()
print("client_b searches dog, should not yield results:", client_b.search("dog"))
print("consultant search dog for client_b, should not yield results:", consultant.search("dog", client_b.get_id()))
print("client_b adds document with dog:", client_b.add(("invoice33",["dog"])))
print("client_b searches dog, should yield 1 result:", client_b.search("dog"))
print("consultant search dog for client_b again, should yield in 1 result:", consultant.search("dog", client_b.get_id()))
print() """

