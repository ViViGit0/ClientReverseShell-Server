import socket
import ssl
import sys
import threading

SERVER_CERT = "server_cert.pem"
SERVER_KEY = "server_key.pem"
SECRET_KEY = "MySuperSecretKey"  # Deve essere la stessa chiave del client

def handle_client(conn, client_addr):
    """Gestisce la connessione sicura con un client."""
    print(f"[+] Connessione da {client_addr}")

    try:
        # Riceve la chiave segreta per autenticazione
        auth_key = conn.recv(1024).decode()
        if auth_key != SECRET_KEY:
            print(f"[!] Autenticazione fallita per {client_addr}")
            conn.sendall(b"AUTH_FAIL")
            conn.close()
            return

        conn.sendall(b"AUTH_SUCCESS")
        print(f"[+] Autenticazione riuscita per {client_addr}")

        while True:
            cmd = input("Comando da inviare: ").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                print("[*] Chiusura connessione...")
                break
            conn.sendall(cmd.encode())
            data = conn.recv(4096)
            if not data:
                print("[!] Connessione chiusa dal client.")
                break
            print(data.decode("utf-8"), end="")

    except Exception as e:
        print(f"[!] Errore: {e}")
    finally:
        conn.close()
        print("[!] Connessione terminata.")

def server(address):
    """Inizializza un server TLS e gestisce più connessioni."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(address)
            s.listen()
            print(f"[*] Server TLS in ascolto su {address[0]}:{address[1]}...")

            # Configura SSL
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

            while True:
                conn, client_addr = s.accept()
                secure_conn = context.wrap_socket(conn, server_side=True)
                thread = threading.Thread(target=handle_client, args=(secure_conn, client_addr), daemon=True)
                thread.start()
                print(f"[!] Client connessi attuali: {threading.active_count() - 1}")

    except Exception as e:
        print(f"[!] Errore del server: {e}")
    except KeyboardInterrupt:
        print("\n[*] Chiusura server...")
        sys.exit()

if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 19876
    server((HOST, PORT))
