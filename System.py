from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(database, sec_param=2**6)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)
