from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(sec_param=2**6)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)

print(client_a.get_key())
print(client_a.get_key())
print(client_b.get_key())

client_a_encrypted_keywords = client_a.write(["cat", "dog"])
print(client_a_encrypted_keywords)

search_dog = client_a.search("dog")
print(search_dog)

# database.search()

