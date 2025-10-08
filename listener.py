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

# Variables globales para la última conexión activa
_last_addr = None
_last_sock = None

def respuesta(mensaje: str):
    """
    Envía una respuesta al último host que envió un mensaje.
    Args:
        mensaje (str): texto de la respuesta
    """
    global _last_addr, _last_sock
    if not _last_addr or not _last_sock:
        print("[listener] No hay contexto de conexión previo para enviar respuesta.")
        return

    ip, port = _last_addr
    full_msg = f"{RESPONSE_PREFIX}:{mensaje}:{platform.node()}:{uuid.getnode()}"
    _last_sock.sendto(full_msg.encode(), _last_addr)
    print(f"[listener] Respuesta enviada a {ip}:{port} → {mensaje}")

def run_listener(bind_ip="0.0.0.0", port=BROADCAST_PORT):
    """
    Escucha UDP en bind_ip:port
    Responde a DISCOVER_REQUEST y procesa distintos payloads
    """
    global _last_addr, _last_sock

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    hostname = platform.node()
    print(f"[listener] escuchando UDP en {bind_ip}:{port} — host: {hostname}")

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            text = data.decode(errors="ignore").strip()
            ip, _ = addr

            # Actualiza el contexto global
            _last_addr = addr
            _last_sock = sock

            

            # Procesar payload dinámico con match-case
            match text:
                case "a1h1":
                    print(f"[listener] Acción 1 ejecutada por {ip}")
                    respuesta("te escucho")
                case "config_dhcp":
                    print(f"[listener] Acción SALMON ejecutada por {ip}")
                    respuesta("hecho")
                case _:
                    print(f"[listener] mensaje desconocido de {ip}: '{text}'")
                    respuesta("unknown")

        except KeyboardInterrupt:
            print("[listener] detenido por usuario.")
            break
        except Exception as e:
            print(f"[listener] error: {e}")

if __name__ == "__main__":
    run_listener()
