
from Client import Client
from Database import Database
from Consultant import Consultant

database = Database()
consultant = Consultant(database)

# Setup all clients
while True:
    amount_clients = input("Enter the amount of clients in this system: \n")
    try:
        amount_clients_int = int(amount_clients)
        if amount_clients_int <= 0 or amount_clients_int > 1000:
            print("The amount of clients should be a non-zero integer smaller than 1000...")
        else:
            break
    except ValueError:
        print("The amount of clients should be a non-zero integer smaller than 1000...")

print("Creating", amount_clients_int,"clients, which might take a while since all keys are generated")
clients = list()
for i in range(amount_clients_int):
    clients.append(Client(id=i, consultant=consultant, database=database))

# ask user input
print("Created", amount_clients_int, "clients")
while True:
    command = input("What would you like to do? `[subject] [action] [data]").split(" ")
    if len(command) != 3:
        print("A command should contain the subject, action, and data...")
        continue
    
    # parse subject
    if command[0] == "c":
        subject = consultant
    elif "c" in command[0]:
        try:
            client_i = int(command[0][1:])
            if client_i <= 0 or client_i >= amount_clients_int:
                print("Could not find the subject, try something like `c` for consultat, or `c0` for the first client.")
            else:
                subject = clients[client_i]
        except ValueError:
            print("Could not find the subject, try something like `c` for consultat, or `c0` for the first client.")
    
    if command[1] == "add":
        # TODO add
        pass
    elif command[1] == "search":
        w = command[2]
        print("Searching for", w, "result:", subject.search(w))
    elif command[1] == "encrypt":
        # TODO encrypt
        pass



    

