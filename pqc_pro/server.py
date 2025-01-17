import socket
import threading
import random
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5000

def generate_self_signed_cert():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DemoTLS"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"DemoServer"),
    ])

    cert_builder = (
        x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
    )

    certificate = cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    return cert_bytes, private_key

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

def handle_client(conn, addr, cert_bytes, private_key):
    print(f"[Server] Connection from {addr}")

    # 1) Wait for certificate request
    data = conn.recv(1024)
    if data == b"REQUEST_CERT":
        # Send certificate
        conn.sendall(cert_bytes)
        print("[Server] Sent certificate.")

    # 2) Diffie-Hellman
    p = 23
    g = 5
    b = random.randint(2, 100)
    B = pow(g, b, p)

    # Receive A from client
    data = conn.recv(1024)
    A = int(data.decode())

    # Send B to client
    conn.sendall(str(B).encode())

    # Compute shared secret
    s = pow(A, b, p)
    print(f"[Server] Shared secret (DH) = {s}")

    # Derive a 16-byte key from s (very naive)
    # Convert s to bytes and slice 16 bytes for AES
    shared_key = str(s).encode()[:16].ljust(16, b'0')

    print("[Server] Ready to chat (encrypted). Type messages here...")
    # 3) Chat loop
    while True:
        # Non-blocking receive - or we can do blocking with a prompt
        try:
            data = conn.recv(4096)
            if not data:
                print("[Server] Client disconnected.")
                break

            decrypted_msg = aes_decrypt(shared_key, data)
            text = decrypted_msg.decode()
            if text.lower() == "exit":
                print("[Server] Client closed the connection.")
                break
            print(f"[Client] {text}")
        except:
            pass

        # Now server can input a message
        server_input = input("[Server] Enter message (or 'exit'): ")
        enc_msg = aes_encrypt(shared_key, server_input.encode())
        conn.sendall(enc_msg)
        if server_input.lower() == "exit":
            print("[Server] Closing connection.")
            break

    conn.close()

def run_server():
    cert_bytes, private_key = generate_self_signed_cert()
    print("[Server] Self-signed cert generated.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen(1)
        print(f"[Server] Listening on {SERVER_HOST}:{SERVER_PORT}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, cert_bytes, private_key)

if __name__ == "__main__":
    run_server()
