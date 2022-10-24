from Client import Client
from Database import Database
from Consultant import Consultant


# database = Database()

consultant = Consultant()
client_a = Client(id=0, consultant=consultant)
client_b = Client(id=1, consultant=consultant)

print(client_a.get_key())
print(client_b.get_key())

# database.search()

