#!/usr/bin/env python3
"""
socket_chat.py

A combined client-server socket programming script with bi-directional communication.
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
    
    # Start threads for sending and receiving
    receive_thread = threading.Thread(target=receive_messages, args=(conn, addr))
    send_thread = threading.Thread(target=send_messages, args=(conn, addr))
    
    receive_thread.start()
    send_thread.start()
    
    # Wait for both threads to finish
    receive_thread.join()
    send_thread.join()
    
    print(f"[-] Connection with {addr} closed.")

def receive_messages(conn, addr):
    """
    Receives messages from the client.

    Parameters:
    - conn: The socket connection object.
    - addr: The address of the client.
    """
    while True:
        try:
            data = conn.recv(1024)  # Buffer size 1024 bytes
            if not data:
                print(f"[-] No data received from {addr}. Closing connection.")
                break

            message = data.decode('utf-8').strip()
            print(f"\n[Client {addr}]: {message}")

            if message.lower() == 'exit':
                print(f"[!] Exit command received from {addr}.")
                break

        except ConnectionResetError:
            print(f"[!] Connection reset by {addr}.")
            break
        except Exception as e:
            print(f"[!] An error occurred while receiving data from {addr}: {e}")
            break

    # Close the connection
    conn.close()

def send_messages(conn, addr):
    """
    Sends messages to the client.

    Parameters:
    - conn: The socket connection object.
    - addr: The address of the client.
    """
    while True:
        try:
            message = input(f"[You to {addr}]: ").strip()
            if not message:
                print("[!] Empty message. Please enter some text.")
                continue

            conn.sendall(message.encode('utf-8'))

            if message.lower() == 'exit':
                print("[*] Exit command sent. Closing connection.")
                break

        except BrokenPipeError:
            print(f"[!] Broken pipe. Unable to send data to {addr}.")
            break
        except Exception as e:
            print(f"[!] An error occurred while sending data to {addr}: {e}")
            break

    # Close the connection
    conn.close()

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

    # Start threads for sending and receiving
    receive_thread = threading.Thread(target=receive_messages_client, args=(client_socket,))
    send_thread = threading.Thread(target=send_messages_client, args=(client_socket,))

    receive_thread.start()
    send_thread.start()

    # Wait for both threads to finish
    receive_thread.join()
    send_thread.join()

    print("[-] Connection closed.")

def receive_messages_client(conn):
    """
    Receives messages from the server.

    Parameters:
    - conn: The socket connection object.
    """
    while True:
        try:
            data = conn.recv(1024)  # Buffer size 1024 bytes
            if not data:
                print("\n[-] No data received from server. Closing connection.")
                break

            message = data.decode('utf-8').strip()
            print(f"\n[Server]: {message}")

            if message.lower() == 'exit':
                print("[!] Exit command received from server.")
                break

        except ConnectionResetError:
            print("\n[!] Connection reset by server.")
            break
        except Exception as e:
            print(f"\n[!] An error occurred while receiving data from server: {e}")
            break

    # Close the connection
    conn.close()

def send_messages_client(conn):
    """
    Sends messages to the server.

    Parameters:
    - conn: The socket connection object.
    """
    while True:
        try:
            message = input("[You to Server]: ").strip()
            if not message:
                print("[!] Empty message. Please enter some text.")
                continue

            conn.sendall(message.encode('utf-8'))

            if message.lower() == 'exit':
                print("[*] Exit command sent. Closing connection.")
                break

        except BrokenPipeError:
            print("\n[!] Broken pipe. Unable to send data to server.")
            break
        except Exception as e:
            print(f"\n[!] An error occurred while sending data to server: {e}")
            break

    # Close the connection
    conn.close()

def parse_arguments():
    """
    Parses command-line arguments.

    Returns:
    - args: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Python Socket Client-Server Chat with Bi-Directional Communication")
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
