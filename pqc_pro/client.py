import socket
import random
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000

def aes_encrypt(key, plaintext):
    iv = b'\x00' * 16  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_decrypt(key, ciphertext):
    iv = b'\x00' * 16  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
    return plaintext

def run_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        # Step 1: Request certificate
        s.sendall(b"REQUEST_CERT")

        # Step 3: Receive certificate, validate it
        cert_bytes = s.recv(4096)
        certificate = x509.load_pem_x509_certificate(cert_bytes)
        public_key = certificate.public_key()
        # Self-signed check
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
        )
        print("[Client] Certificate is valid (self-signed).")

        # Step 4: Diffie-Hellman
        p = 23
        g = 5
        a = random.randint(2, 100)
        A = pow(g, a, p)

        # Send A to server
        s.sendall(str(A).encode())

        # Receive B
        data = s.recv(1024)
        B = int(data.decode())

        # Compute shared secret
        s_val = pow(B, a, p)
        print(f"[Client] Shared secret (DH) = {s_val}")

        # Derive a 16-byte key (naive)
        shared_key = str(s_val).encode()[:16].ljust(16, b'0')

        print("[Client] Ready to chat. Type messages here...")
        while True:
            client_input = input("[Client] Enter message (or 'exit'): ")
            enc_msg = aes_encrypt(shared_key, client_input.encode())
            s.sendall(enc_msg)
            if client_input.lower() == "exit":
                print("[Client] Closing connection.")
                break

            # Now read server reply
            data = s.recv(4096)
            if not data:
                print("[Client] Server disconnected.")
                break
            decrypted_reply = aes_decrypt(shared_key, data).decode()
            if decrypted_reply.lower() == "exit":
                print("[Client] Server closed the connection.")
                break

            print(f"[Server] {decrypted_reply}")

if __name__ == "__main__":
    run_client()
