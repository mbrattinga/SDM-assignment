from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = b'Sixteen byte key'

cipher = AES.new(key, AES.MODE_ECB)

for i in range(10):
    ciphertext = cipher.encrypt(pad(bytes(i), AES.block_size))
    print(int.from_bytes(ciphertext, 'big') % 10)
