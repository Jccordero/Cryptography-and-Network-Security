from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def main():
    key = get_random_bytes(32)   # 32 bytes = 256 bits
    iv = get_random_bytes(12)    # 12 bytes = 96 bits, estándar en GCM

    print("Clave AES-256 (hex):", key.hex())
    print("IV / Nonce (hex):   ", iv.hex())

    aad = b"metadata_version=1.2"

    with open("mensaje_original.txt", "rb") as f:
        plaintext = f.read()


    cipher_enc = AES.new(key, AES.MODE_GCM, nonce=iv)

    cipher_enc.update(aad)

    ciphertext, tag = cipher_enc.encrypt_and_digest(plaintext)

    with open("cifrado_gcm.bin", "wb") as f:
        f.write(ciphertext)

    with open("tag_gcm.bin", "wb") as f:
        f.write(tag)

    print("\n[CIFRADO]")
    print("Ciphertext guardado en: cifrado_gcm.bin")
    print("Tag de autenticación en:", tag.hex())


    cipher_dec = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher_dec.update(aad)

    try:
        plaintext_rec = cipher_dec.decrypt_and_verify(ciphertext, tag)
        print("\n[DESCIFRADO CORRECTO]")
        print("Descifrado OK, tag válido.")
        print("Mensaje recuperado:")
        print(plaintext_rec.decode("utf-8", errors="replace"))
    except ValueError as e:
        print("\n[ERROR]")
        print("Fallo de autenticación al descifrar (no debería pasar aquí):", e)


    tampered = bytearray(ciphertext)
    if len(tampered) == 0:
        print("\n[AVISO] El ciphertext está vacío, no se puede manipular.")
        return

    index = len(tampered) // 2
    tampered[index] ^= 0x01  # flip de un bit

    with open("cifrado_gcm_tampered.bin", "wb") as f:
        f.write(tampered)

    print("\n[ATAQUE SIMULADO]")
    print(f"Se ha modificado 1 byte del ciphertext en la posición {index}.")
    print("Ciphertext manipulado guardado en: cifrado_gcm_tampered.bin")


    cipher_dec2 = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher_dec2.update(aad)

    try:
        plaintext_tampered = cipher_dec2.decrypt_and_verify(bytes(tampered), tag)
        print("\n[RESULTADO INESPERADO]")
        print("¡Se descifró sin error, algo va mal! (no debería ocurrir)")
        print(plaintext_tampered.decode("utf-8", errors="replace"))
    except ValueError as e:
        print("\n[DESCIFRADO DEL CIFRADO MANIPULADO]")
        print("Fallo de autenticación, datos detectados como manipulados.")
        print("Error:", e)


if __name__ == "__main__":
    main()

