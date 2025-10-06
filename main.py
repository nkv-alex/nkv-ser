#!/usr/bin/env python3
"""
mi-comando.py — versión tolerante a argumentos.
Comportamiento: si no se pasa subcomando, ejecuta 'discover' por defecto.
"""

import argparse
import socket
import sys
import time
import uuid
import platform

BROADCAST_PORT = 50000
BUFFER_SIZE = 1024
DISCOVER_TIMEOUT = 2.0
DISCOVER_MESSAGE_PREFIX = "DISCOVER_REQUEST"
RESPONSE_PREFIX = "DISCOVER_RESPONSE"
PAYLOAD = "a1h1"

def discover_and_send(broadcast_ip="255.255.255.255", port=BROADCAST_PORT, send=False, timeout=DISCOVER_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    token = str(uuid.uuid4())[:8]
    discover_msg = f"{DISCOVER_MESSAGE_PREFIX}:{token}"
    sock.sendto(discover_msg.encode(), (broadcast_ip, port))
    print(f"[discover] enviado broadcast '{discover_msg}' a {broadcast_ip}:{port}, esperando {timeout}s...")

    discovered = {}
    t0 = time.time()
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            text = data.decode(errors="ignore")
            ip, _ = addr
            if text.startswith(RESPONSE_PREFIX):
                parts = text.split(":", 2)
                if len(parts) >= 3:
                    _, hostname, nodeid = parts
                else:
                    hostname = text
                    nodeid = ""
                discovered[ip] = {"hostname": hostname.strip(), "nodeid": nodeid.strip()}
                print(f"[discover] respuesta de {ip} -> {hostname}")
        except socket.timeout:
            break
        except Exception as e:
            print(f"[discover] error recibiendo: {e}")
            if time.time() - t0 > timeout:
                break

    if not discovered:
        print("[discover] no se detectaron listeners.")
        return discovered

    print(f"[discover] encontrados {len(discovered)} hosts:")
    for ip, info in discovered.items():
        print(f"  - {ip}  ({info.get('hostname')})")

    if send:
        print(f"[discover] enviando payload '{PAYLOAD}' a cada host detectado...")
        for ip in discovered.keys():
            try:
                sock.sendto(PAYLOAD.encode(), (ip, port))
                print(f"[discover] payload enviado a {ip}")
            except Exception as e:
                print(f"[discover] fallo al enviar a {ip}: {e}")

    return discovered

def main():
    parser = argparse.ArgumentParser(prog="mi-comando", description="Comando LAN cooperativo (modo discover por defecto si no se especifica)")
    sub = parser.add_subparsers(dest="cmd")

    p_discover = sub.add_parser("discover", help="Descubre listeners en la LAN")
    p_discover.add_argument("--broadcast", default="255.255.255.255", help="IP de broadcast")
    p_discover.add_argument("--port", "-p", type=int, default=BROADCAST_PORT, help=f"Puerto UDP (por defecto {BROADCAST_PORT})")
    p_discover.add_argument("--timeout", "-t", type=float, default=DISCOVER_TIMEOUT, help="Timeout para recibir respuestas (s)")
    p_discover.add_argument("--send", action="store_true", help=f"Enviar '{PAYLOAD}' a los hosts detectados (usar con precaución)")


    # legacy action
    p_action = sub.add_parser("action", help="(legacy) start/stop/status")
    p_action.add_argument("accion", choices=["start","stop","status"])



    # ---- Manejo tolerante: si no hay subcomando -> forzamos discover por defecto ----
    if len(sys.argv) == 1:
        # comportamiento por defecto: discover con valores por defecto
        print("[main] no se especificó subcomando — ejecutando 'discover' por defecto.")
        discover_and_send()
        return

    # parseamos normalmente
    args = parser.parse_args()

    if args.cmd == "discover":
        discover_and_send(broadcast_ip=args.broadcast, port=args.port, send=args.send, timeout=args.timeout)

    elif args.cmd == "action":
        if args.accion == "start":
            print("Iniciando servicio...")
        elif args.accion == "stop":
            print("Deteniendo servicio...")
        elif args.accion == "status":
            print("Estado del servicio: OK")
        else:
            print(f"Acción no reconocida: {args.accion}")
            sys.exit(1)

if __name__ == "__main__":
    main()