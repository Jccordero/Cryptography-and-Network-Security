from Crypto.Random import get_random_bytes

key = get_random_bytes(32)

aes_nonce = get_random_bytes(16)

chacha_nonce = get_random_bytes(12)

print("Clave (hex):       ", key.hex())
print("AES-CTR nonce (hex):", aes_nonce.hex())
print("ChaCha20 nonce (hex):", chacha_nonce.hex())

