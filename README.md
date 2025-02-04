# ClientReverseShell-Server
Client reverse shell + server / Autenticazione e cifratura TLS/SSL
Python 3.12.8
Questo progetto implementa una shell remota sicura utilizzando cifratura TLS e autenticazione tramite chiave segreta.
Installa OpenSSL
Genera certificati SSL = openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
Avvia il Server
Avvia il Client
La chiave segreta predefinita per l'autenticazione è: MySuperSecretKey
