#! /usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key_size = 32 # 32 bytes 
block_size = 16 # tamaño de bloque AES

key = os.urandom(key_size)
iv = os.urandom(block_size)

print("Clave AES-256 (hex):", key.hex())
print("IV (hex):", iv.hex())

with open("mensaje_original.txt", "rb") as f:
    plaintext = f.read()

padded = pad(plaintext, block_size)

from Crypto.Cipher import AES

cipher_ecb = AES.new(key, AES.MODE_ECB)
ciphertext_ecb = cipher_ecb.encrypt(padded)

with open("mensaje_ecb.bin", "wb") as f:
    f.write(ciphertext_ecb)

cipher_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
ciphertext_cbc = cipher_cbc.encrypt(padded)

with open("mensaje_cbc.bin", "wb") as f:
    f.write(ciphertext_cbc)

