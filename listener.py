#!/usr/bin/env python3
"""
listener.py — escucha en la LAN por discovery y mensajes
Uso seguro: solo en redes/hosts bajo tu control
"""
import socket
import platform
import uuid

BROADCAST_PORT = 50000
BUFFER_SIZE = 1024
DISCOVER_PREFIX = "DISCOVER_REQUEST"
RESPONSE_PREFIX = "DISCOVER_RESPONSE"
PAYLOAD = "a1h1"

def run_listener(bind_ip="0.0.0.0", port=BROADCAST_PORT):
    """
    Escucha UDP en bind_ip:port
    Responde a DISCOVER_REQUEST y procesa PAYLOAD seguro
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    hostname = platform.node()
    print(f"[listener] escuchando UDP en {bind_ip}:{port} — host: {hostname}")

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            text = data.decode(errors="ignore")
            ip, _ = addr

            # Responder a discovery
            if text.startswith(DISCOVER_PREFIX):
                reply = f"{RESPONSE_PREFIX}:{hostname}:{uuid.getnode()}"
                sock.sendto(reply.encode(), addr)
                print(f"[listener] recibido DISCOVER de {ip}, respondido.")

            # Procesar payload seguro
            elif text.strip() == PAYLOAD:
                print(f"[listener] PAYLOAD recibido de {ip}: '{PAYLOAD}'")
                # Aquí puedes poner cualquier acción segura que quieras ejecutar
                # Ejemplo: print("Acción ejecutada!")

            else:
                print(f"[listener] mensaje desconocido de {ip}: {text}")

        except KeyboardInterrupt:
            print("[listener] detenido por usuario.")
            break
        except Exception as e:
            print(f"[listener] error: {e}")

if __name__ == "__main__":
    run_listener()
