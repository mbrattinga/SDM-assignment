from Client import Client
from Database import Database
from Consultant import Consultant


# database = Database()

consultant = Consultant(sec_param=2**6)
client_a = Client(id=0, consultant=consultant)
client_b = Client(id=1, consultant=consultant)

print(client_a.get_key())
print(client_a.get_key())
print(client_b.get_key())

client_a_encrypted_keywords = client_a.write(["cat", "dog"])
print(client_a_encrypted_keywords)

# database.search()

