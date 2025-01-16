#!/usr/bin/env python3
"""
socket_chat.py

A combined client-server socket programming script.
Run in server mode:
    python3 socket_chat.py server --host 0.0.0.0 --port 65432

Run in client mode:
    python3 socket_chat.py client --host 127.0.0.1 --port 65432
"""

import socket
import threading
import argparse
import sys

def handle_client(conn, addr):
    """
    Handles communication with a connected client.

    Parameters:
    - conn: The socket connection object.
    - addr: The address of the client.
    """
    print(f"[+] New connection from {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(1024)  # Buffer size 1024 bytes
                if not data:
                    print(f"[-] No data received from {addr}. Closing connection.")
                    break

                message = data.decode('utf-8').strip()
                print(f"[{addr}] {message}")

                if message.lower() == 'exit':
                    print(f"[!] Exit command received from {addr}. Closing connection.")
                    break

                # Send a response back to the client
                response = f"Server received: {message}"
                conn.sendall(response.encode('utf-8'))

            except ConnectionResetError:
                print(f"[!] Connection reset by {addr}.")
                break
            except Exception as e:
                print(f"[!] An error occurred with {addr}: {e}")
                break

    print(f"[-] Connection with {addr} closed.")

def start_server(host='0.0.0.0', port=65432):
    """
    Starts the server to listen for incoming connections.

    Parameters:
    - host: The hostname or IP address to bind the server.
    - port: The port number to bind the server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow reuse of the address
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
    except socket.error as e:
        print(f"[!] Bind failed. Error: {e}")
        sys.exit()

    server_socket.listen()
    print(f"[+] Server started on {host}:{port}")
    print("[*] Waiting for connections...")

    try:
        while True:
            conn, addr = server_socket.accept()
            # Create a new thread for each client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True  # Allows program to exit even if threads are running
            client_thread.start()
            print(f"[+] Started thread for {addr}")
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
    finally:
        server_socket.close()

def start_client(server_host='127.0.0.1', server_port=65432):
    """
    Starts the client to connect to the server.

    Parameters:
    - server_host: The server's hostname or IP address to connect to.
    - server_port: The server's port number to connect to.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_host, server_port))
    except socket.error as e:
        print(f"[!] Connection failed. Error: {e}")
        sys.exit()

    print(f"[+] Connected to server at {server_host}:{server_port}")

    try:
        while True:
            message = input("Enter message (type 'exit' to close): ").strip()
            if not message:
                print("[!] Empty message. Please enter some text.")
                continue

            client_socket.sendall(message.encode('utf-8'))

            if message.lower() == 'exit':
                print("[*] Exit command sent. Closing connection.")
                break

            try:
                data = client_socket.recv(1024)
                if not data:
                    print("[!] No response from server. Closing connection.")
                    break

                response = data.decode('utf-8')
                print(f"[Server]: {response}")
            except ConnectionResetError:
                print("[!] Connection reset by server.")
                break
            except Exception as e:
                print(f"[!] An error occurred: {e}")
                break

    except KeyboardInterrupt:
        print("\n[!] Client shutting down.")
    finally:
        client_socket.close()
        print("[-] Connection closed.")

def parse_arguments():
    """
    Parses command-line arguments.

    Returns:
    - args: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Python Socket Client-Server Chat")
    subparsers = parser.add_subparsers(dest='mode', help='Mode to run the script in: server or client')

    # Server sub-command
    server_parser = subparsers.add_parser('server', help='Run script in server mode')
    server_parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server (default: 0.0.0.0)')
    server_parser.add_argument('--port', type=int, default=65432, help='Port to bind the server (default: 65432)')

    # Client sub-command
    client_parser = subparsers.add_parser('client', help='Run script in client mode')
    client_parser.add_argument('--host', type=str, default='127.0.0.1', help='Server host to connect to (default: 127.0.0.1)')
    client_parser.add_argument('--port', type=int, default=65432, help='Server port to connect to (default: 65432)')

    args = parser.parse_args()

    if args.mode not in ['server', 'client']:
        parser.print_help()
        sys.exit(1)

    return args

def main():
    """
    The main function that runs based on the provided mode.
    """
    args = parse_arguments()

    if args.mode == 'server':
        start_server(host=args.host, port=args.port)
    elif args.mode == 'client':
        start_client(server_host=args.host, server_port=args.port)
    else:
        print("[!] Invalid mode selected. Choose 'server' or 'client'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
