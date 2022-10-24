from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(sec_param=2**6, database=database)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)

client_a.write(["cat", "dog"])
client_a.write(["cat"])

print("Results for giraffe:", client_a.search("giraffe"))
print("Results for dog:", client_a.search("dog"))
print("Results for cat:", client_a.search("cat"))


consultant.write(client_a, ["mum", "dad"])
consultant.write(client_a, ["mum", "dad", "uncle"])

print("Results for giraffe:", consultant.search(client_a, "giraffe"))
print("Results for cat:", consultant.search(client_a, "cat"))
print("Results for dog:", consultant.search(client_a, "dog"))
print("Results for mum:", consultant.search(client_a, "mum"))
print("Results for dad:", consultant.search(client_a, "dad"))
print("Results for uncle:", consultant.search(client_a, "uncle"))
