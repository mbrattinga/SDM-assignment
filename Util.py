
def XOR(x, y):
    if not len(x) == len(y):
        Exception("XOR two values of unequal length is insupported: ", x, y)
        print("AAAAAAAAAAAAAAA DIFFERENT LENGHTS0", x, y)

    """ int_x = int.from_bytes(x, 'big')
    int_y = int.from_bytes(y, 'big')
    int_z = int_x ^ int_y
    return int_z.to_bytes(len(x), 'big') """

    return bytes(a ^ b for (a, b) in zip(x, y))    

def myprint(*msg):
    # print(msg)
    pass