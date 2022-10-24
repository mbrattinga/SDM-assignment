from Client import Client
from Database import Database
from Consultant import Consultant


database = Database()

consultant = Consultant(sec_param=2**6, database=database)
client_a = Client(id=0, consultant=consultant, database=database)
client_b = Client(id=1, consultant=consultant, database=database)

client_a.write(["cat", "dog"])
client_a.write(["cat"])

print(f"{client_a.id = }", "Results for giraffe:", client_a.search("giraffe"))
print(f"{client_a.id = }", "Results for dog:", client_a.search("dog"))
print(f"{client_a.id = }", "Results for cat:", client_a.search("cat"))


consultant.write(client_a, ["mum", "dad"])
consultant.write(client_a, ["mum", "dad", "uncle"])

print("consultant:", "Results for giraffe:", consultant.search(client_a, "giraffe"))
print("consultant:", "Results for cat:", consultant.search(client_a, "cat"))
print("consultant:", "Results for dog:", consultant.search(client_a, "dog"))
print("consultant:", "Results for mum:", consultant.search(client_a, "mum"))
print("consultant:", "Results for dad:", consultant.search(client_a, "dad"))
print("consultant:", "Results for uncle:", consultant.search(client_a, "uncle"))

print(f"{client_a.id = }", "Results for mum:", client_a.search("mum"))
print(f"{client_a.id = }", "Results for dad:", client_a.search("dad"))
print(f"{client_a.id = }", "Results for uncle:", client_a.search("uncle"))


# client b
client_b.write(["sdm", "scc"])
client_b.write(["bio", "sys", "crp"])
client_b.write(["bio", "sdm"])


print(f"{client_b.id = }", "Results for sdm:", client_b.search("sdm"))
print(f"{client_b.id = }", "Results for sys:", client_b.search("sys"))
print(f"{client_b.id = }", "Results for bio:", client_b.search("bio"))

print("consultant:", "Results for giraffe:", consultant.search(client_b, "giraffe"))
print("consultant:", "Results for cat:", consultant.search(client_b, "cat"))
print("consultant:", "Results for dad:", consultant.search(client_b, "dad"))
print("consultant:", "Results for sdm:", consultant.search(client_b, "sdm"))
print("consultant:", "Results for sys:", consultant.search(client_b, "sys"))
print("consultant:", "Results for bio:", consultant.search(client_b, "bio"))

consultant.write(client_b, ["graduate"])

print("consultant:", "Results for graduate:", consultant.search(client_b, "graduate"))
print(f"{client_b.id = }", "Results for graduate:", client_b.search("graduate"))

