from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
nonce = get_random_bytes(12)

print("Clave ChaCha20 (hex):", key.hex())
print("Nonce (hex):", nonce.hex())

with open("mensaje1.txt", "rb") as f:
    m1 = f.read()

with open("mensaje2.txt", "rb") as f:
    m2 = f.read()

cipher1 = ChaCha20.new(key=key, nonce=nonce)
c1 = cipher1.encrypt(m1)

with open("cifrado1.bin", "wb") as f:
    f.write(c1)

cipher2 = ChaCha20.new(key=key, nonce=nonce)
c2 = cipher2.encrypt(m2)

with open("cifrado2.bin", "wb") as f:
    f.write(c2)

