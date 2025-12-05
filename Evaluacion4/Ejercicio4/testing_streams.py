import time
from Crypto.Cipher import AES, ChaCha20

KEY_HEX = "745ade8a4bb8e77b919f885957068f9d757a2de9355335816e180cb597f88cfe"
AES_IV_HEX = "0908ef79d2c5af7224426eec65882c37"
CHACHA_NONCE_HEX = "225aaa806b721268a6ebc7c0"

key = bytes.fromhex(KEY_HEX)
aes_iv_bytes = bytes.fromhex(AES_IV_HEX)
chacha_nonce = bytes.fromhex(CHACHA_NONCE_HEX)

aes_initial_value = int.from_bytes(aes_iv_bytes, "big")

with open("archivo_grande.bin", "rb") as f:
    data = f.read()

size_mb = len(data) / (1024 * 1024)
print(f"Tamaño del archivo: {size_mb:.2f} MB")

start = time.perf_counter()
cipher_aes = AES.new(
    key,
    AES.MODE_CTR,
    nonce=b"",                 # nonce vacío
    initial_value=aes_initial_value
)
ciphertext_aes = cipher_aes.encrypt(data)
end = time.perf_counter()
aes_time = end - start
print(f"Tiempo AES-256-CTR: {aes_time:.4f} segundos ({size_mb / aes_time:.2f} MB/s)")

start = time.perf_counter()
cipher_chacha = ChaCha20.new(key=key, nonce=chacha_nonce)
ciphertext_chacha = cipher_chacha.encrypt(data)
end = time.perf_counter()
chacha_time = end - start
print(f"Tiempo ChaCha20:    {chacha_time:.4f} segundos ({size_mb / chacha_time:.2f} MB/s)")

with open("archivo_grande_aes_ctr.bin", "wb") as f:
    f.write(ciphertext_aes)

with open("archivo_grande_chacha20.bin", "wb") as f:
    f.write(ciphertext_chacha)

