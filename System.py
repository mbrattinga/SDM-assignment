from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant()
client_a = Client(id=0)
client_a = Client(id=1)


database.search()

