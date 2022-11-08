
def XOR(x, y):
    if not len(x) == len(y):
        Exception("XOR two values of unequal length is insupported: ", x, y)

    int_x = int.from_bytes(x, 'big')
    int_y = int.from_bytes(y, 'big')
    int_z = int_x ^ int_y
    return int_z.to_bytes(len(x), 'big')