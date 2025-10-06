#!/usr/bin/env python3
import argparse
import socket
import sys
import time
import uuid
import fcntl
import struct
import json
import os

BROADCAST_PORT = 50000
BUFFER_SIZE = 1024
DISCOVER_TIMEOUT = 2.0
DISCOVER_MESSAGE_PREFIX = "DISCOVER_REQUEST"
RESPONSE_PREFIX = "DISCOVER_RESPONSE"
PAYLOAD = "a1h1"
HOSTS_FILE = "hosts.json"


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


def save_hosts(discovered):
    """Guarda los hosts descubiertos en un archivo JSON."""
    try:
        with open(HOSTS_FILE, "w") as f:
            json.dump(discovered, f, indent=2)
        print(f"[store] {len(discovered)} hosts guardados en {HOSTS_FILE}")
    except Exception as e:
        print(f"[store] Error al guardar hosts: {e}")


def load_hosts():
    """Carga los hosts guardados desde el archivo JSON."""
    if not os.path.exists(HOSTS_FILE):
        print("[store] No hay hosts almacenados.")
        return {}
    try:
        with open(HOSTS_FILE, "r") as f:
            hosts = json.load(f)
        print(f"[store] {len(hosts)} hosts cargados desde {HOSTS_FILE}")
        return hosts
    except Exception as e:
        print(f"[store] Error leyendo {HOSTS_FILE}: {e}")
        return {}


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
                hostname = parts[1] if len(parts) > 1 else ip
                nodeid = parts[2] if len(parts) > 2 else ""
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

    save_hosts(discovered)

    if send:
        send_to_hosts(discovered, port=port)

    return discovered


def send_to_hosts(hosts, port=BROADCAST_PORT, payload=PAYLOAD):
    """Envía un payload a una lista de hosts (dict o archivo cargado)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[send] enviando payload '{payload}' a {len(hosts)} hosts...")
    for ip in hosts.keys():
        try:
            sock.sendto(payload.encode(), (ip, port))
            print(f"[send] payload enviado a {ip}")
        except Exception as e:
            print(f"[send] fallo al enviar a {ip}: {e}")


def main():
    parser = argparse.ArgumentParser(
        prog="mi-comando",
        description="Comando LAN cooperativo con persistencia de hosts"
    )
    sub = parser.add_subparsers(dest="cmd")

    p_discover = sub.add_parser("discover", help="Descubre listeners en la LAN")
    p_discover.add_argument("--iface", "-i", default="enp0s3", help="Interfaz de red (por defecto enp0s3)")
    p_discover.add_argument("--port", "-p", type=int, default=BROADCAST_PORT, help=f"Puerto UDP (por defecto {BROADCAST_PORT})")
    p_discover.add_argument("--timeout", "-t", type=float, default=DISCOVER_TIMEOUT, help="Timeout para recibir respuestas (s)")
    p_discover.add_argument("--send", action="store_true", help=f"Enviar '{PAYLOAD}' a los hosts detectados")

    p_send = sub.add_parser("send", help="Envía payload a hosts guardados")
    p_send.add_argument("--port", "-p", type=int, default=BROADCAST_PORT, help=f"Puerto UDP (por defecto {BROADCAST_PORT})")
    p_send.add_argument("--payload", default=PAYLOAD, help="Mensaje a enviar")

    if len(sys.argv) == 1:
        print("[main] no se especificó subcomando — ejecutando 'discover' por defecto.")
        discover_and_send()
        return

    args = parser.parse_args()

    if args.cmd == "discover":
        discover_and_send(interface=args.iface, port=args.port, send=args.send, timeout=args.timeout)
    elif args.cmd == "send":
        hosts = load_hosts()
        if hosts:
            send_to_hosts(hosts, port=args.port, payload=args.payload)
        else:
            print("[send] No hay hosts registrados.")


if __name__ == "__main__":
    main()
