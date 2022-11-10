from Client import Client
from Database import Database
from Consultant import Consultant

from Crypto.Hash import MD5

database = Database()

consultant = Consultant(database)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)

md5_to_files = {}

files = [("0", ["cat"]),("1", ["cat", "dog", "cow"]), ("2", ["cat", "cow"])]
# files = [("0", ["cat"]),("1", ["cat", "dog", "cow"]), ("2", ["cat", "cow"])]
print(f"{files = }")
for file in files:
    md5_to_files[MD5.new(bytes(file[0], 'utf-8')).digest()] = file[0]
# (A_s, T_s) = client_a.encrypt(files)
(A_s, T_s, A_d, T_d) = client_a.encrypt(files)
print()
print("client_a searches cat:", [md5_to_files[id] for id in client_a.search("cat")])
print("client_a searches dog:", [md5_to_files[id] for id in client_a.search("dog")])
print("client_a searches cow:", [md5_to_files[id] for id in client_a.search("cow")])
# print("client_a searches lion:", [md5_to_files[id] for id in client_a.search("lion")])

client_a.delete(("0", ["cat"]))
print("search cat after deleting document 0", [md5_to_files[id] for id in client_a.search("cat")])
print("search dog after deleting document 0", [md5_to_files[id] for id in client_a.search("dog")])
print("search cow after deleting document 0", [md5_to_files[id] for id in client_a.search("cow")])
# print("search lion after deleting document 0", [md5_to_files[id] for id in client_a.search("lion")])

consultant.delete(("1", ["cat", "dog", "cow"]), client_a.get_id())
print("search cat after consultant deleting document 1", [md5_to_files[id] for id in client_a.search("cat")])
print("search dog after consultant deleting document 1", [md5_to_files[id] for id in client_a.search("dog")])
print("search cow after consultant deleting document 1", [md5_to_files[id] for id in client_a.search("cow")])

client_a.delete(("2", ["cat", "cow"]))
print("search cat after deleting document 2", [md5_to_files[id] for id in client_a.search("cat")])
print("search dog after deleting document 2", [md5_to_files[id] for id in client_a.search("dog")])
print("search cow after deleting document 2", [md5_to_files[id] for id in client_a.search("cow")])

#########################################################################################################

""" print("consultant search dog for client_a, should yield 1 result:", [md5_to_files[id] for id in consultant.search("dog", client_a.get_id())])
print()
md5_to_files[MD5.new(bytes("myfile", 'utf-8')).digest()] = "myfile"
print("client_a adds document with cow:", client_a.add(("myfile",["cow"])))

print("client_a searches cow again, now should yield 1 result:", [md5_to_files[id] for id in client_a.search("cow")])

md5_to_files[MD5.new(bytes("myinvoice", 'utf-8')).digest()] = "myinvoice"
print("consultant adds document with cow for client_a:", consultant.add(("myinvoice",["cow"]), client_a.get_id()))

print("client_a searches cow again, now should yield 2 results:", [md5_to_files[id] for id in client_a.search("cow")])
print("consultant searches cow for client_a, now should yield 2 result:", [md5_to_files[id] for id in consultant.search("cow", client_a.get_id())])
print()
print("client_b searches dog, should not yield results:", [md5_to_files[id] for id in client_b.search("dog")])
print("consultant search dog for client_b, should not yield results:", [md5_to_files[id] for id in consultant.search("dog", client_b.get_id())])

md5_to_files[MD5.new(bytes("invoice33", 'utf-8')).digest()] = "invoice33"
print("client_b adds document with dog:", client_b.add(("invoice33",["dog"])))

print("client_b searches dog, should yield 1 result:", [md5_to_files[id] for id in client_b.search("dog")])
print("consultant search dog for client_b again, should yield in 1 result:", [md5_to_files[id] for id in consultant.search("dog", client_b.get_id())])
print() """

