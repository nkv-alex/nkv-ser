#!/usr/bin/env python3
import argparse
import socket
import sys
import time
import uuid
import fcntl
import struct

BROADCAST_PORT = 50000
BUFFER_SIZE = 1024
DISCOVER_TIMEOUT = 2.0
DISCOVER_MESSAGE_PREFIX = "DISCOVER_REQUEST"
RESPONSE_PREFIX = "DISCOVER_RESPONSE"
PAYLOAD = "a1h1"


def get_interface_broadcast(interface):
    """Devuelve la dirección de broadcast de una interfaz como '192.168.1.255'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8919,  # SIOCGIFBRDADDR
            struct.pack('256s', interface.encode('utf-8')[:15])
        )[20:24])
    except Exception as e:
        print(f"[net] Error obteniendo broadcast de {interface}: {e}")
        return "255.255.255.255"


def discover_and_send(interface="enp0s3", port=BROADCAST_PORT, send=False, timeout=DISCOVER_TIMEOUT):
    broadcast_ip = get_interface_broadcast(interface)
    print(f"[discover] usando interfaz '{interface}' con broadcast {broadcast_ip}")

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
    parser = argparse.ArgumentParser(
        prog="mi-comando",
        description="Comando LAN cooperativo (modo discover por defecto si no se especifica)"
    )
    sub = parser.add_subparsers(dest="cmd")

    p_discover = sub.add_parser("discover", help="Descubre listeners en la LAN")
    p_discover.add_argument("--iface", "-i", default="enp0s3", help="Interfaz de red (por defecto enp0s3)")
    p_discover.add_argument("--port", "-p", type=int, default=BROADCAST_PORT, help=f"Puerto UDP (por defecto {BROADCAST_PORT})")
    p_discover.add_argument("--timeout", "-t", type=float, default=DISCOVER_TIMEOUT, help="Timeout para recibir respuestas (s)")
    p_discover.add_argument("--send", action="store_true", help=f"Enviar '{PAYLOAD}' a los hosts detectados")

    if len(sys.argv) == 1:
        print("[main] no se especificó subcomando — ejecutando 'discover' por defecto.")
        discover_and_send()
        return

    args = parser.parse_args()

    if args.cmd == "discover":
        discover_and_send(interface=args.iface, port=args.port, send=args.send, timeout=args.timeout)


if __name__ == "__main__":
    main()
