
def XOR(x, y):
    if not len(x) == len(y):
        Exception("XOR two values of unequal length is insupported: ", x, y)
        print("AAAAAAAAAAAAAAA DIFFERENT LENGHTS", x, y)

    return bytes(a ^ b for (a, b) in zip(x, y))    

def myprint(*msg):
    # print(msg)
    pass