from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(sec_param=2**6)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)

client_a.write(["cat", "dog"])
client_a.write(["cat"])

print("Results for giraffe:", client_a.search("giraffe"))
print("Results for dog:", client_a.search("dog"))
print("Results for cat:", client_a.search("cat"))

# database.search()

