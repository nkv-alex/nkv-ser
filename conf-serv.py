#!/usr/bin/env python3
# conf-serv.py
# Script para Ubuntu 22.04: detectar interfaces, preguntar tipo, actualizar netplan,
# habilitar forwarding, crear reglas iptables, persistirlas, DHCP y envío UDP.

import os
import subprocess
import shutil
from datetime import datetime
import ipaddress
import yaml
import sys
from pathlib import Path
import re
import socket
import struct
import fcntl
import json
import time
import uuid
import argparse

NETPLAN_DEFAULT_PATH = "/etc/netplan/01-nat.yaml"
BACKUP_DIR = "/etc/netplan/backups_nat_helper"
IPTABLES_RULES_V4 = "/etc/iptables/rules.v4"
SYSCTL_CONF = "/etc/sysctl.conf"

# dict global para interfaces detectadas
interfaces = {}

def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)

def backup_file(path):
    if os.path.exists(path):
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(BACKUP_DIR, f"{os.path.basename(path)}.{ts}.bak")
        print(f"[INFO] Backup {path} -> {dest}")
        shutil.copy2(path, dest)

def detect_interfaces():
    """Detecta interfaces con IPs y pregunta si son internas o externas.
    Guarda el resultado en la variable global 'interfaces' y lo devuelve.
    """
    global interfaces

    try:
        res = run(
            "ip -o -4 addr show | awk '{print $2,$4}' | "
            "grep -Ev '^(lo|docker|veth|br-|virbr|vmnet|tap)' || true",
            check=False
        )
    except Exception as e:
        print(f"[ERROR] Al ejecutar ip: {e}")
        return {}

    out = res.stdout.strip()
    if not out:
        print("[ERROR] No se encontraron interfaces con IPv4 asignada.")
        return {}

    interfaces.clear()
    print("\n=== Detección de interfaces ===")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        iface, addr = parts[0], parts[1]
        try:
            ipif = ipaddress.IPv4Interface(addr)
        except Exception:
            print(f"[WARN] Dirección inválida en {iface}: {addr}, la salto.")
            continue

        print(f"\nInterfaz detectada: {iface}")
        print(f"  Dirección IP: {ipif}")
        suggested = "i" if ipif.ip.is_private else "e"
        tipo = input(f"¿Esta interfaz es interna (i) o externa (e)? [{suggested}]: ").strip().lower()
        if tipo == "":
            tipo = suggested
        if tipo not in ("i", "e", "internal", "external"):
            tipo = suggested

        t = "internal" if tipo.startswith("i") else "external"
        interfaces[iface] = {"ip": str(ipif), "type": t}

    print("\nResumen de selección:")
    intern = [k for k, v in interfaces.items() if v["type"] == "internal"]
    extern = [k for k, v in interfaces.items() if v["type"] == "external"]
    print(f"  Internas: {intern}")
    print(f"  Externas: {extern}")

    return interfaces

def build_netplan_yaml(existing_yaml, interfaces_param):
    """
    existing_yaml: dict (parsed YAML) o {}
    interfaces_param: dict como devuelve detect_interfaces()
    Devuelve YAML dict modificado.
    """
    if not isinstance(existing_yaml, dict):
        existing_yaml = {}

    net = existing_yaml.get("network", {})
    version = net.get("version", 2)
    renderer = net.get("renderer", "networkd")
    ethernets = net.get("ethernets", {}) or {}

    for iface, data in interfaces_param.items():
        ip = data.get("ip")
        tipo = data.get("type")
        if not ip or not tipo:
            continue
        iface_data = ethernets.get(iface, {})

        if tipo == "external":
            iface_data["dhcp4"] = True
            iface_data["optional"] = iface_data.get("optional", True)
            iface_data.pop("addresses", None)
            iface_data.pop("routes", None)
        else:
            iface_data["dhcp4"] = False
            iface_data["addresses"] = [ip]
            if "nameservers" not in iface_data:
                iface_data["nameservers"] = {"addresses": ["8.8.8.8", "1.1.1.1"]}
            iface_data.pop("optional", None)
        ethernets[iface] = iface_data

    new_net = {
        "version": version,
        "renderer": renderer,
        "ethernets": ethernets
    }
    return {"network": new_net}

def write_netplan_file(interfaces_param):
    """
    Localiza primer archivo en /etc/netplan/ y lo modifica.
    Si no existe, crea NETPLAN_DEFAULT_PATH.
    """
    netplan_dir = "/etc/netplan"
    netplan_files = [f for f in os.listdir(netplan_dir) if f.endswith(".yaml") or f.endswith(".yml")] if os.path.isdir(netplan_dir) else []
    if netplan_files:
        path = os.path.join(netplan_dir, netplan_files[0])
    else:
        os.makedirs(os.path.dirname(NETPLAN_DEFAULT_PATH), exist_ok=True)
        path = NETPLAN_DEFAULT_PATH

    existing_yaml = {}
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                existing_yaml = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[WARN] No se pudo parsear {path}: {e}. Se trabajará sobre contenido vacío.")
            existing_yaml = {}

    backup_file(path)
    print(f"[INFO] Modificando netplan: {path}")

    modified = build_netplan_yaml(existing_yaml, interfaces_param)

    try:
        with open(path, "w") as f:
            yaml.safe_dump(modified, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except Exception as e:
        print(f"[ERROR] No se pudo escribir {path}: {e}")
        return False

    print(f"[INFO] Netplan actualizado -> {path}")
    return True

def enable_ip_forwarding():
    backup_file(SYSCTL_CONF)
    lines = []
    if os.path.exists(SYSCTL_CONF):
        with open(SYSCTL_CONF, "r") as f:
            lines = f.readlines()
    new_lines = []
    found = False
    for line in lines:
        if line.strip().startswith("net.ipv4.ip_forward"):
            new_lines.append("net.ipv4.ip_forward=1\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append("\n# Enabled by conf-serv.py\nnet.ipv4.ip_forward=1\n")
    with open(SYSCTL_CONF, "w") as f:
        f.writelines(new_lines)
    try:
        run("sysctl -p", check=True)
    except Exception:
        print("[WARN] sysctl -p falló o devolvió error. Revisa /etc/sysctl.conf")
    print("[INFO] IP forwarding habilitado")

def build_iptables_rules(interfaces_param):
    internals = [k for k,v in interfaces_param.items() if v["type"]=="internal"]
    externals = [k for k,v in interfaces_param.items() if v["type"]=="external"]

    lines = ["*nat",
             ":PREROUTING ACCEPT [0:0]",
             ":INPUT ACCEPT [0:0]",
             ":OUTPUT ACCEPT [0:0]",
             ":POSTROUTING ACCEPT [0:0]"]
    for ext in externals:
        lines.append(f"-A POSTROUTING -o {ext} -j MASQUERADE")
    lines.append("COMMIT")
    lines.append("*filter")
    lines.append(":INPUT ACCEPT [0:0]")
    lines.append(":FORWARD ACCEPT [0:0]")
    lines.append(":OUTPUT ACCEPT [0:0]")
    lines.append("-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    for intf in internals:
        for ext in externals:
            lines.append(f"-A FORWARD -i {intf} -o {ext} -j ACCEPT")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"

def save_iptables_rules(rules_text):
    if os.path.exists(IPTABLES_RULES_V4):
        backup_file(IPTABLES_RULES_V4)
    os.makedirs(os.path.dirname(IPTABLES_RULES_V4), exist_ok=True)
    with open(IPTABLES_RULES_V4, "w") as f:
        f.write("# Generated by conf-serv.py\n")
        f.write(rules_text)
    try:
        run(f"iptables-restore < {IPTABLES_RULES_V4}", check=True)
    except Exception:
        print("[WARN] iptables-restore falló; intenta aplicar manualmente o revisa iptables.")
    print(f"[INFO] Reglas iptables guardadas en {IPTABLES_RULES_V4}")

def try_enable_persistent():
    try:
        run("which apt >/dev/null 2>&1", check=True)
        print("[INFO] Intentando instalar iptables-persistent (si falta)...")
        run("DEBIAN_FRONTEND=noninteractive apt-get update -y", check=False)
        run("DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent", check=False)
        run("systemctl enable netfilter-persistent.service", check=False)
        run("systemctl restart netfilter-persistent.service", check=False)
    except Exception:
        print("[WARN] No se pudo habilitar iptables-persistent automáticamente.")

def apply_netplan():
    try:
        run("netplan apply", check=True)
        print("[INFO] Netplan aplicado")
    except Exception:
        print("[WARN] netplan apply falló. Revisa el YAML y ejecuta 'sudo netplan apply' manualmente.")

def validate_interfaces(interfaces_param):
    intern = [k for k,v in interfaces_param.items() if v["type"]=="internal"]
    extern = [k for k,v in interfaces_param.items() if v["type"]=="external"]
    if not intern:
        print("[ERROR] No hay interfaces marcadas como internas. Se necesita al menos una.")
        return False
    if not extern:
        print("[ERROR] No hay interfaces marcadas como externas. Se necesita al menos una.")
        return False
    return True

def nat_configuration():
    if os.geteuid() != 0:
        print("Ejecuta este script con sudo/root")
        sys.exit(1)

    print("=== Configuración NAT automática Ubuntu 22.04 ===")
    detect_interfaces()  # actualiza global interfaces
    if not interfaces:
        print("[ERROR] No hay interfaces detectadas. Abortando.")
        return

    if not validate_interfaces(interfaces):
        print("[ERROR] Validación de interfaces falló. Abortando.")
        return

    ok = write_netplan_file(interfaces)
    if not ok:
        print("[ERROR] Error al escribir netplan. Abortando antes de tocar iptables.")
        return

    enable_ip_forwarding()

    rules_text = build_iptables_rules(interfaces)
    save_iptables_rules(rules_text)

    try_enable_persistent()

    apply_netplan()

    print("\n[FIN] Configuración NAT completada.")
    print("Revisa los archivos:")
    print(f" - Netplan modificado en /etc/netplan/")
    print(f" - Backups en {BACKUP_DIR}")
    print(f" - Reglas iptables en {IPTABLES_RULES_V4}")

def configure_ssh():
    print("=== Configuración personalizada de SSH ===")

    config_path = "/etc/ssh/sshd_config"
    backup_path = f"{config_path}.bak"

    if not os.path.exists(backup_path):
        print(f"[INFO] Generando backup: {backup_path}")
        run(f"sudo cp {config_path} {backup_path}")
    else:
        print(f"[INFO] Backup existente: {backup_path}")

    print("\n=== Parámetros SSH ===")
    puerto = input("Puerto SSH (default 22): ").strip() or "22"
    root_login = input("¿Permitir login de root? (yes/no) [no]: ").strip().lower() or "no"

    print("\n=== Detección de usuarios locales ===")
    res = run("awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd", check=False)
    users = res.stdout.strip().splitlines()
    if users:
        print("Usuarios detectados:")
        for u in users:
            print(f"  - {u}")
    else:
        print("[WARN] No se encontraron usuarios normales en el sistema.")
    allowed = input("\nUsuarios permitidos por SSH (espacio = todos): ").strip()
    allow_users = f"AllowUsers {allowed}" if allowed else ""

    with open(config_path, "r") as f:
        lines = f.readlines()

    def set_param(param, value):
        pattern = re.compile(rf'^\s*#?\s*{re.escape(param)}\b', re.IGNORECASE)
        replaced = False
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = f"{param} {value}\n"
                replaced = True
                break
        if not replaced:
            lines.append(f"\n{param} {value}\n")

    set_param("Port", puerto)
    set_param("PermitRootLogin", root_login)
    set_param("PasswordAuthentication", "yes")
    set_param("PubkeyAuthentication", "yes")
    set_param("ChallengeResponseAuthentication", "no")
    set_param("UsePAM", "yes")
    set_param("X11Forwarding", "no")
    set_param("AllowTcpForwarding", "yes")
    if allow_users:
        set_param("AllowUsers", allowed)

    tmp_file = "/tmp/sshd_config_tmp"
    with open(tmp_file, "w") as f:
        f.writelines(lines)

    run(f"sudo mv {tmp_file} {config_path}")
    run("sudo chmod 600 /etc/ssh/sshd_config")

    print("\n[INFO] Aplicando cambios y reiniciando SSH...")
    run("sudo systemctl enable ssh", check=False)
    run("sudo systemctl restart ssh", check=False)

    status = run("sudo systemctl is-active ssh", check=False)
    ip = run("hostname -I | awk '{print $1}'", check=False)
    print(f"\n[OK] SSH operativo en {ip.stdout.strip()}:{puerto}")
    print(f"[INFO] RootLogin: {root_login}")
    if allowed:
        print(f"[INFO] Usuarios permitidos: {allowed}")
    print(f"[INFO] Backup en: {backup_path}")

def configure_dhcp():
    if os.geteuid() != 0:
        print("Ejecuta este script con sudo/root")
        sys.exit(1)

    print("=== Configuración automática de DHCP (isc-dhcp-server) ===")
    run("apt update -y", check=False)
    run("apt install -y isc-dhcp-server", check=False)

    dhcp_conf = "/etc/dhcp/dhcpd.conf"
    dhcp_iface_conf = "/etc/default/isc-dhcp-server"
    backup_file(dhcp_conf)
    backup_file(dhcp_iface_conf)

    # Detectar interfaces internas
    detect_interfaces()
    candidate = [(iface, v["ip"]) for iface, v in interfaces.items() if v["type"] == "internal"]
    if not candidate:
        print("[ERROR] No se detectaron interfaces privadas para DHCP.")
        return

    print("\nInterfaces candidatas para DHCP:")
    for i, (iface, ip) in enumerate(candidate, 1):
        print(f"  {i}. {iface} ({ip})")

    idx = input(f"Selecciona interfaz a usar como servidor DHCP [1]: ").strip()
    try:
        sel_index = int(idx)-1 if idx else 0
        iface_sel, ip_sel = candidate[sel_index]
    except Exception:
        iface_sel, ip_sel = candidate[0]

    ip_obj = ipaddress.IPv4Interface(ip_sel)
    red = ip_obj.network
    gateway = str(ip_obj.ip)

    hosts = list(red.hosts())
    # defensivo: elegir valores por defecto razonables sin IndexError
    default_start = str(hosts[10]) if len(hosts) > 20 else str(hosts[1]) if len(hosts) > 2 else str(hosts[0])
    default_end = str(hosts[-10]) if len(hosts) > 20 else str(hosts[-1]) if len(hosts) > 2 else str(hosts[-1])

    print(f"\nRed detectada: {red}")
    print(f"Gateway propuesto: {gateway}")
    rango_ini = input(f"Inicio del rango DHCP [por defecto {default_start}]: ").strip() or default_start
    rango_fin = input(f"Fin del rango DHCP [por defecto {default_end}]: ").strip() or default_end
    dns = input("DNS (por defecto 8.8.8.8,1.1.1.1): ").strip() or "8.8.8.8,1.1.1.1"

    print("[INFO] Configurando interfaz de servicio...")
    if os.path.exists(dhcp_iface_conf):
        with open(dhcp_iface_conf, "r") as f:
            lines = f.readlines()
    else:
        lines = []
    new_lines = []
    found = False
    for line in lines:
        if line.strip().startswith("INTERFACESv4="):
            new_lines.append(f"INTERFACESv4=\"{iface_sel}\"\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"\nINTERFACESv4=\"{iface_sel}\"\n")
    with open(dhcp_iface_conf, "w") as f:
        f.writelines(new_lines)

    print("[INFO] Escribiendo configuración DHCP...")
    dhcp_config = f"""
# Generated by conf-serv.py
default-lease-time 600;
max-lease-time 7200;
authoritative;

subnet {red.network_address} netmask {red.netmask} {{
  range {rango_ini} {rango_fin};
  option routers {gateway};
  option subnet-mask {red.netmask};
  option domain-name-servers {dns};
}}
"""
    with open(dhcp_conf, "w") as f:
        f.write(dhcp_config.strip() + "\n")

    print("[INFO] Reiniciando servicio DHCP...")
    run("systemctl enable isc-dhcp-server", check=False)
    run("systemctl restart isc-dhcp-server", check=False)

    status = run("systemctl is-active isc-dhcp-server", check=False)
    if "active" in status.stdout:
        print(f"[OK] DHCP activo en interfaz {iface_sel}")
        print(f"[INFO] Rango: {rango_ini} → {rango_fin}")
    else:
        print("[ERROR] DHCP no pudo iniciarse. Revisa con: journalctl -u isc-dhcp-server")

def send_to_hosts(payload, port=50000, timeout=2.0, send=True):
    """
    Descubre hosts en todas las interfaces internas definidas globalmente y
    envía un payload UDP.

    Args:
        payload (str): Mensaje que se enviará a los hosts descubiertos.
    """
    import socket, struct, fcntl, time, uuid, json, os

    DISCOVER_MESSAGE_PREFIX = "DISCOVER_REQUEST"
    RESPONSE_PREFIX = "DISCOVER_RESPONSE"
    HOSTS_FILE = "hosts.json"

    global interfaces
    if not interfaces:
        print("[INFO] No hay interfaces cargadas. Detectando...")
        detect_interfaces()
    internals = [iface for iface, v in interfaces.items() if v["type"] == "internal"]
    if not internals:
        print("[ERROR] No se detectaron interfaces internas. Ejecuta detect_interfaces() antes.")
        return {}

    def get_broadcast(iface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t
