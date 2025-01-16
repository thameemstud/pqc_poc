#!/usr/bin/env python3

import sys
import socket
import pickle
import threading
import random
import hashlib
import os

# For PQC KEM (Kyber512) using python-oqs
import oqs

# For AES encryption/decryption
from Crypto.Cipher import AES


#####################################
#  GLOBAL PARAMS & HELPER FUNCTIONS #
#####################################

# A small Diffie-Hellman prime and generator for DEMO ONLY (NOT secure in production).
DH_PRIME = 0xFD7F53811D75122952DF4A9C2EECE4E7F611817F
DH_GENERATOR = 5

def generate_dh_keypair():
    """Generate a basic DH keypair (private_key, public_key)."""
    private_key = random.randrange(2, DH_PRIME - 2)
    public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
    return private_key, public_key

def compute_shared_secret(their_public, my_private):
    """Compute the classical Diffie-Hellman shared secret."""
    return pow(their_public, my_private, DH_PRIME)

def sha256_bytes(*parts):
    """Concatenate byte-strings and return their SHA-256 hash (32 bytes)."""
    combined = b"".join(parts)
    return hashlib.sha256(combined).digest()

def derive_hybrid_key(dh_secret_int, pqc_shared_key_bytes):
    """
    Combine the classic DH secret (as int) with the PQC shared key (bytes)
    and derive a final 32-byte AES key using SHA-256.
    """
    # Convert DH secret (int) to bytes
    dh_secret_bytes = dh_secret_int.to_bytes((dh_secret_int.bit_length() + 7) // 8, 'big')
    # Hash them together
    return sha256_bytes(dh_secret_bytes, pqc_shared_key_bytes)

def encrypt_message(aes_key, plaintext):
    """Encrypt plaintext (bytes) with AES in CBC mode + PKCS7 padding."""
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_message(aes_key, iv_and_cipher):
    """Decrypt with AES CBC + remove PKCS7 padding."""
    iv = iv_and_cipher[:16]
    ciphertext = iv_and_cipher[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]


###################################
#           SERVER CODE           #
###################################

def run_server(host='127.0.0.1', port=4444):
    print("[Server] Starting...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[Server] Listening on {host}:{port}")

    client_socket, addr = server_socket.accept()
    print(f"[Server] Client connected from {addr}")

    # =========== HYBRID KEY EXCHANGE ===========
    # 1) Server generates ephemeral DH keypair + Kyber key pair
    server_dh_private, server_dh_public = generate_dh_keypair()

    # Using python-oqs for Kyber512
    server_kem = oqs.KeyEncapsulation("Kyber512")
    server_kyber_public_key = server_kem.generate_keypair()  
    # server_kyber_public_key is a 'bytes' object with the public key.

    # 2) Server -> Client: Send (server_dh_public, server_kyber_public_key)
    server_data = {
        "server_dh_public": server_dh_public,
        "server_kyber_public_key": server_kyber_public_key
    }
    client_socket.sendall(pickle.dumps(server_data))
    print("[Server] Sent ephemeral DH & Kyber public data to client.")

    # 3) Server receives (client_dh_public, pqc_ciphertext)
    client_hybrid_data = pickle.loads(client_socket.recv(4096))
    client_dh_public = client_hybrid_data["client_dh_public"]
    client_pqc_ciphertext = client_hybrid_data["client_pqc_ciphertext"]
    print("[Server] Received client's DH public & PQC ciphertext.")

    # 4) Server computes final shared key
    #    a) Classic DH
    dh_secret = compute_shared_secret(client_dh_public, server_dh_private)
    #    b) Decrypt Kyber ciphertext
    server_pqc_shared_key = server_kem.decap_secret(client_pqc_ciphertext)
    #    c) Combine
    aes_key = derive_hybrid_key(dh_secret, server_pqc_shared_key)
    print("[Server] Shared key derived. Ready for secure chat.")

    # =========== ENCRYPTED CHAT ===========
    def receive_messages():
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                msg = decrypt_message(aes_key, data).decode()
                if msg == "/close":
                    print("[Server] Client requested to close.")
                    break
                print(f"[Client -> Server] {msg}")
            except:
                break
        client_socket.close()
        print("[Server] Connection closed by client or error.")
    
    threading.Thread(target=receive_messages, daemon=True).start()

    print("[Server] You can now type messages. Type /close to end.")
    while True:
        msg_out = input("")
        if not msg_out:
            continue
        enc = encrypt_message(aes_key, msg_out.encode())
        client_socket.sendall(enc)
        if msg_out == "/close":
            print("[Server] Closing connection.")
            client_socket.close()
            break


###################################
#           CLIENT CODE           #
###################################

def run_client(host='127.0.0.1', port=4444):
    print("[Client] Connecting to server...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"[Client] Connected to {host}:{port}")

    # =========== HYBRID KEY EXCHANGE ===========
    # 1) Client receives (server_dh_public, server_kyber_public_key)
    server_data = pickle.loads(client_socket.recv(4096))
    server_dh_public = server_data["server_dh_public"]
    server_kyber_public_key = server_data["server_kyber_public_key"]
    print("[Client] Received server's DH public & Kyber public key.")

    # 2) Client generates ephemeral DH keypair, then uses server_kyber_public_key
    #    to encapsulate a PQC shared key.
    client_dh_private, client_dh_public = generate_dh_keypair()

    client_kem = oqs.KeyEncapsulation("Kyber512")
    # Encapsulate a shared key using the server's public key
    client_pqc_ciphertext, client_pqc_shared_key = client_kem.encap_secret(server_kyber_public_key)

    # 3) Send (client_dh_public, pqc_ciphertext) to server
    client_hybrid_data = {
        "client_dh_public": client_dh_public,
        "client_pqc_ciphertext": client_pqc_ciphertext
    }
    client_socket.sendall(pickle.dumps(client_hybrid_data))
    print("[Client] Sent DH public & PQC ciphertext to server.")

    # 4) Client computes final shared key
    #    a) Classic DH
    dh_secret = compute_shared_secret(server_dh_public, client_dh_private)
    #    b) Already have PQC shared key from encap_secret
    aes_key = derive_hybrid_key(dh_secret, client_pqc_shared_key)
    print("[Client] Shared key derived. Ready for secure chat.")

    # =========== ENCRYPTED CHAT ===========
    def receive_messages():
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                msg = decrypt_message(aes_key, data).decode()
                if msg == "/close":
                    print("[Client] Server requested to close.")
                    break
                print(f"[Server -> Client] {msg}")
            except:
                break
        client_socket.close()
        print("[Client] Connection closed or error.")
    
    threading.Thread(target=receive_messages, daemon=True).start()

    print("[Client] You can now type messages. Type /close to end.")
    while True:
        msg_out = input("")
        if not msg_out:
            continue
        enc = encrypt_message(aes_key, msg_out.encode())
        client_socket.sendall(enc)
        if msg_out == "/close":
            print("[Client] Closing connection.")
            client_socket.close()
            break


#######################
#   MAIN ENTRYPOINT   #
#######################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hybrid_dh_oqs.py [server|client]")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        print("Unknown mode. Use 'server' or 'client'.")
