#!/usr/bin/env python3
"""
listener.py — escucha en la LAN por discovery y mensajes
Uso seguro: solo en redes/hosts bajo tu control
"""
import socket
import platform
import uuid
import subprocess
import yaml
import os

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

def forzar_dhcp():
    try:
        res = subprocess.run(
            "ip -o -4 addr show | awk '{print $2}' | grep -Ev '^(lo|docker|veth|br-|virbr|vmnet|tap)' || true",
            shell=True, capture_output=True, text=True, check=False
        )
        interfaces = [i.strip() for i in res.stdout.splitlines() if i.strip()]
        if not interfaces:
            print("[WARN] No se detectaron interfaces activas.")
            return

        netplan_dir = "/etc/netplan"
        if not os.path.isdir(netplan_dir):
            print(f"[ERROR] No existe {netplan_dir}")
            return

        yaml_files = [os.path.join(netplan_dir, f) for f in os.listdir(netplan_dir) if f.endswith(".yaml")]
        if not yaml_files:
            print("[WARN] No hay archivos YAML de Netplan.")
            return

        for file_path in yaml_files:
            print(f"[INFO] Reescribiendo {file_path} ...")

            data = {
                "network": {
                    "version": 2,
                    "renderer": "NetworkManager",
                    "ethernets": {}
                }
            }

            for iface in interfaces:
                data["network"]["ethernets"][iface] = {
                    "dhcp4": True,
                    "dhcp4-overrides": {
                        "use-routes": True,
                        "use-dns": True
                    }
                }

            # Forzar escritura con sudo
            tmp_file = f"/tmp/{os.path.basename(file_path)}"
            with open(tmp_file, "w") as f:
                yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)

            subprocess.run(f"sudo cp {tmp_file} {file_path}", shell=True, check=True)
            subprocess.run(f"sudo chmod 644 {file_path}", shell=True, check=False)

        subprocess.run("sudo netplan apply", shell=True, check=True)
        print(f"[OK] Interfaces {interfaces} configuradas vía DHCP (servidor 192.168.1.10)")

    except Exception as e:
        print(f"[ERROR] {e}")




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

            # Si es un mensaje DISCOVER
            if text.startswith(DISCOVER_PREFIX):
                respuesta("DISCOVER MSG")
                print(f"[listener] recibido DISCOVER de {ip}, respondido.")
                continue

            # Procesar payload dinámico con match-case
            match text:
                case "test":
                    print(f"[listener] Acción 1 ejecutada por {ip}")
                    respuesta("te escucho")
                case "config_dhcp":
                    print(f"[listener] Acción SALMON ejecutada por {ip}")
                    respuesta("hecho")
                case _:
                    print(f"[listener] mensaje desconocido de {ip}: '{text}'")
                    respuesta("none")







        except KeyboardInterrupt:
            print("[listener] detenido por usuario.")
            break
        except Exception as e:
            print(f"[listener] error: {e}")

if __name__ == "__main__":
    run_listener()
