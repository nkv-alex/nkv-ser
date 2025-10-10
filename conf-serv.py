#!/usr/bin/env python3
# conf-serv.py
# Script for Ubuntu 22.04: detect interfaces, ask type, update netplan, enable forwarding, create iptables rules and persist them.

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

# ==============================
# MAIN VARIABLES
# ==============================
UDP_PORT = 50000
NETPLAN_DEFAULT_PATH = "/etc/netplan/01-nat.yaml"
BACKUP_DIR = "/etc/netplan/backups_nat_helper"
IPTABLES_RULES_V4 = "/etc/iptables/rules.v4"
SYSCTL_CONF = "/etc/sysctl.conf"
JSON_FILE = "interfaces.json"
interfaces = {}  
DNS_ZONE = "empresa.local"
DNS_FILE = f"/etc/bind/db.{DNS_ZONE}"
CACHE_FILE = "/var/lib/dns_autoupdate/hosts_cache.txt"

# ==============================
# OS FUNCTIONS
# ==============================

def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)

def backup_file(path):
    if os.path.exists(path):
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(BACKUP_DIR, f"{os.path.basename(path)}.{ts}.bak")
        print(f"[INFO] Backup {path} -> {dest}")
        shutil.copy2(path, dest)

# ==============================
# CONFIG NAT
# ==============================

def detect_interfaces():

    """Detect interfaces with IPs, use those from JSON if they exist,
    only ask for new ones and update the file.
    """
    global interfaces

    # --- 1. Load existing JSON ---
    if os.path.exists(JSON_FILE):
        try:
            with open(JSON_FILE, "r") as f:
                interfaces = json.load(f)
            print(f"[INFO] Configuration loaded from {JSON_FILE}")
        except Exception as e:
            print(f"[WARN] Could not read {JSON_FILE}: {e}")
            interfaces = {}
    else:
        interfaces = {}

    # --- 2. Detect system interfaces ---
    try:
        res = subprocess.run(
            "ip -o -4 addr show | awk '{print $2,$4}' | grep -Ev '^(lo|docker|veth|br-|virbr|vmnet|tap)' || true",
            capture_output=True,
            text=True,
            check=False,
            shell=True  # <- important
        )
    except Exception as e:
        print(f"[ERROR] Error running 'ip': {e}")
        return {}
    out = res.stdout.strip()
    if not out:
        print("[ERROR] No interfaces with assigned IPv4 found.")
        return interfaces

    print("\n=== Interface detection ===")

    # --- 3. Process detected interfaces ---
    updated = False
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue

        iface, addr = parts[0], parts[1]
        try:
            ipif = ipaddress.IPv4Interface(addr)
        except Exception:
            print(f"[WARN] Invalid address in {iface}: {addr}, skipping.")
            continue

        # If already exists and matches, do not ask
        if iface in interfaces and interfaces[iface].get("ip") == str(ipif):
            print(f"[OK] {iface} unchanged → type: {interfaces[iface]['type']}")
            continue

        # Ask only if new or changed
        print(f"\nDetected interface: {iface}")
        print(f"  IP address: {ipif}")
        suggested = "i" if ipif.ip.is_private else "e"
        tipo = input(f"Is this interface internal (i) or external (e)? [{suggested}]: ").strip().lower()
        if tipo == "":
            tipo = suggested
        if tipo not in ("i", "e", "internal", "external"):
            tipo = suggested

        t = "internal" if tipo.startswith("i") else "external"
        interfaces[iface] = {"ip": str(ipif), "type": t}
        updated = True

    # --- 4. Save changes if there were updates ---
    if updated:
        try:
            with open(JSON_FILE, "w") as f:
                json.dump(interfaces, f, indent=4)
            print(f"[INFO] Configuration updated in {JSON_FILE}")
        except Exception as e:
            print(f"[ERROR] Could not save {JSON_FILE}: {e}")
    else:
        print("[INFO] No changes in interfaces.")

    # --- 5. Show summary ---
    intern = [k for k, v in interfaces.items() if v["type"] == "internal"]
    extern = [k for k, v in interfaces.items() if v["type"] == "external"]
    print("\nFinal summary:")
    print(f"  Internal: {intern}")
    print(f"  External: {extern}")

    return interfaces

def build_netplan_yaml(existing_yaml, interfaces):
    """
    existing_yaml: dict (parsed YAML) or {}
    interfaces: dict as returned by detect_interfaces()
    Returns modified YAML dict.
    """
    if not isinstance(existing_yaml, dict):
        existing_yaml = {}

    # Ensure base structure
    net = existing_yaml.get("network", {})
    # keep version/renderer if they exist, otherwise set defaults
    version = net.get("version", 2)
    renderer = net.get("renderer", "networkd")
    ethernets = net.get("ethernets", {}) or {}

    # Update/add interfaces by type
    for iface, data in interfaces.items():
        ip = data.get("ip")
        tipo = data.get("type")
        if not ip or not tipo:
            continue
        iface_data = ethernets.get(iface, {})

        if tipo == "external":
            # external: DHCP
            iface_data["dhcp4"] = True
            # keep optional if exists, otherwise set true to avoid boot blocks
            iface_data["optional"] = iface_data.get("optional", True)
            # remove addresses/routes/nameservers if was static and now dhcp
            iface_data.pop("addresses", None)
            iface_data.pop("routes", None)
            # Do not touch existing global nameservers
        else:
            # internal: static
            iface_data["dhcp4"] = False
            iface_data["addresses"] = [ip]
            # If no nameservers defined, add some defaults (can change)
            if "nameservers" not in iface_data:
                iface_data["nameservers"] = {"addresses": ["8.8.8.8", "1.1.1.1"]}
            # Do not force external gateway; if you want to add a specific route, comment here
            # Keep any previous config (routes, mtu, etc.)
            iface_data.pop("optional", None)  # normally internal not optional
        ethernets[iface] = iface_data

    # Rebuild structure
    new_net = {
        "version": version,
        "renderer": renderer,
        "ethernets": ethernets
    }
    return {"network": new_net}

def write_netplan_file(interfaces):
    """
    Finds first file in /etc/netplan/ and modifies it.
    If not exists, creates NETPLAN_DEFAULT_PATH.
    """
    # find file to modify
    netplan_files = [f for f in os.listdir("/etc/netplan") if f.endswith(".yaml") or f.endswith(".yml")] if os.path.isdir("/etc/netplan") else []
    if netplan_files:
        path = os.path.join("/etc/netplan", netplan_files[0])
    else:
        # create directory if not exists
        os.makedirs(os.path.dirname(NETPLAN_DEFAULT_PATH), exist_ok=True)
        path = NETPLAN_DEFAULT_PATH

    # read existing
    existing_yaml = {}
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                existing_yaml = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[WARN] Could not parse {path}: {e}. Working with empty content.")
            existing_yaml = {}

    # backup
    backup_file(path)
    print(f"[INFO] Modifying netplan: {path}")

    # build new YAML dict
    modified = build_netplan_yaml(existing_yaml, interfaces)

    # write keeping readable style
    try:
        with open(path, "w") as f:
            yaml.safe_dump(modified, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except Exception as e:
        print(f"[ERROR] Could not write {path}: {e}")
        return False

    print(f"[INFO] Netplan updated -> {path}")
    return True

def enable_ip_forwarding():
    backup_file(SYSCTL_CONF)
    # read if exists, if not create
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
        print("[WARN] sysctl -p failed or returned error. Check /etc/sysctl.conf")
    print("[INFO] IP forwarding enabled")

def build_iptables_rules(interfaces):
    """
    interfaces: detected dict. Builds rules using all internals->externals.
    """
    internals = [k for k,v in interfaces.items() if v["type"]=="internal"]
    externals = [k for k,v in interfaces.items() if v["type"]=="external"]

    lines = ["*nat",
             ":PREROUTING ACCEPT [0:0]",
             ":INPUT ACCEPT [0:0]",
             ":OUTPUT ACCEPT [0:0]",
             ":POSTROUTING ACCEPT [0:0]"]
    # Add MASQUERADE for each external interface
    for ext in externals:
        # Masquerade everything going out via ext
        lines.append(f"-A POSTROUTING -o {ext} -j MASQUERADE")
    lines.append("COMMIT")
    lines.append("*filter")
    lines.append(":INPUT ACCEPT [0:0]")
    lines.append(":FORWARD ACCEPT [0:0]")
    lines.append(":OUTPUT ACCEPT [0:0]")
    # Allow established connections
    lines.append("-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    # Allow traffic from internals to externals
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
        print("[WARN] iptables-restore failed; try to apply manually or check iptables.")
    print(f"[INFO] iptables rules saved in {IPTABLES_RULES_V4}")

def try_enable_persistent():
    # Only for Debian/Ubuntu: try to install iptables-persistent
    try:
        run("which apt >/dev/null 2>&1", check=True)
        print("[INFO] Trying to install iptables-persistent (if missing)...")
        run("DEBIAN_FRONTEND=noninteractive apt-get update -y", check=False)
        run("DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent", check=False)
        run("systemctl enable netfilter-persistent.service", check=False)
        run("systemctl restart netfilter-persistent.service", check=False)
    except Exception:
        print("[WARN] Could not enable iptables-persistent automatically.")

def apply_netplan():
    try:
        run("netplan apply", check=True)
        print("[INFO] Netplan applied")
    except Exception:
        print("[WARN] netplan apply failed. Check the YAML and run 'sudo netplan apply' manually.")

def validate_interfaces(interfaces):
    intern = [k for k,v in interfaces.items() if v["type"]=="internal"]
    extern = [k for k,v in interfaces.items() if v["type"]=="external"]
    if not intern:
        print("[ERROR] No interfaces marked as internal. At least one is required.")
        return False
    if not extern:
        print("[ERROR] No interfaces marked as external. At least one is required.")
        return False
    return True

def nat_configuration():
    if os.geteuid() != 0:
        print("Run this script with sudo/root")
        sys.exit(1)

    print("=== Automatic NAT configuration Ubuntu 22.04 ===")
    interfaces = detect_interfaces()
    if not interfaces:
        print("[ERROR] No interfaces detected. Aborting.")
        return

    if not validate_interfaces(interfaces):
        print("[ERROR] Interface validation failed. Aborting.")
        return

    # Modify existing netplan (backup included)
    ok = write_netplan_file(interfaces)
    if not ok:
        print("[ERROR] Error writing netplan. Aborting before touching iptables.")
        return

    # Enable IP forwarding
    enable_ip_forwarding()

    # Generate and save iptables rules
    rules_text = build_iptables_rules(interfaces)
    save_iptables_rules(rules_text)

    # Try persistence (iptables-persistent)
    try_enable_persistent()

    # Apply netplan
    apply_netplan()

    print("\n[END] NAT configuration completed.")
    print("Check the files:")
    print(f" - Netplan modified in /etc/netplan/")
    print(f" - Backups in {BACKUP_DIR}")
    print(f" - iptables rules in {IPTABLES_RULES_V4}")

# ==============================
# CONFIG SSH
# ==============================

def configure_ssh():
    print("=== Custom SSH configuration ===")

    config_path = "/etc/ssh/sshd_config"
    backup_path = f"{config_path}.bak"

    # 1️⃣ Backup
    if not os.path.exists(backup_path):
        print(f"[INFO] Generating backup: {backup_path}")
        run(f"sudo cp {config_path} {backup_path}")
    else:
        print(f"[INFO] Existing backup: {backup_path}")

    # 2️⃣ Requested parameters
    print("\n=== SSH parameters ===")
    puerto = input("SSH port (default 22): ").strip() or "22"
    root_login = input("Allow root login? (yes/no) [no]: ").strip().lower() or "no"

    # 3️⃣ User detection
    print("\n=== Local user detection ===")
    res = run("awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd", check=False)
    users = res.stdout.strip().splitlines()
    if users:
        print("Detected users:")
        for u in users:
            print(f"  - {u}")
    else:
        print("[WARN] No normal users found on the system.")
    allowed = input("\nUsers allowed by SSH (space = all): ").strip()
    allow_users = f"AllowUsers {allowed}" if allowed else ""

    # 4️⃣ Read the file
    with open(config_path, "r") as f:
        lines = f.readlines()

    def set_param(param, value):
        """
        Finds the corresponding line in sshd_config, uncomments if necessary,
        and changes the value. If not exists, adds at the end.
        """
        pattern = re.compile(rf'^\s*#?\s*{re.escape(param)}\b', re.IGNORECASE)
        replaced = False
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = f"{param} {value}\n"
                replaced = True
                break
        if not replaced:
            lines.append(f"\n{param} {value}\n")

    # 5️⃣ Apply key parameters
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

    # 6️⃣ Save
    tmp_file = "/tmp/sshd_config_tmp"
    with open(tmp_file, "w") as f:
        f.writelines(lines)

    run(f"sudo mv {tmp_file} {config_path}")
    run("sudo chmod 600 /etc/ssh/sshd_config")

    # 7️⃣ Reiniciar servicio
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

# ==============================
# CONFIG DHCP
# ==============================

def configure_dhcp():
    """
    Loads internal interfaces from interfaces.json and configures DHCP server for one of them.
    """
    print("=== Automatic DHCP configuration (isc-dhcp-server) ===")

    # Load interfaces.json
    if not os.path.exists("interfaces.json"):
        print("[ERROR] interfaces.json not found.")
        return
    with open("interfaces.json", "r") as f:
        interfaces = json.load(f)

    # Filter internal interfaces
    internal_ifaces = [(iface, data["ip"]) for iface, data in interfaces.items() if data["type"] == "internal"]
    if not internal_ifaces:
        print("[ERROR] No internal interfaces found in interfaces.json.")
        return

    # Install package
    print("[INFO] Checking isc-dhcp-server installation...")
    run("apt update -y", check=False)
    run("apt install -y isc-dhcp-server", check=False)

    dhcp_conf = "/etc/dhcp/dhcpd.conf"
    dhcp_iface_conf = "/etc/default/isc-dhcp-server"
    backup_file(dhcp_conf)
    backup_file(dhcp_iface_conf)

    print("\nCandidate interfaces for DHCP:")
    for i, (iface, ip) in enumerate(internal_ifaces, 1):
        print(f"  {i}. {iface} ({ip})")

    idx = input(f"Select interface to use as DHCP server [1]: ").strip()
    iface_sel, ip_sel = internal_ifaces[int(idx)-1] if idx else internal_ifaces[0]

    ip_obj = ipaddress.IPv4Interface(ip_sel)
    red = ip_obj.network
    gateway = str(ip_obj.ip)

    print(f"\nDetected network: {red}")
    print(f"Proposed gateway: {gateway}")
    rango_ini = input(f"DHCP range start [default {list(red.hosts())[10]}]: ").strip() or str(list(red.hosts())[10])
    rango_fin = input(f"DHCP range end [default {list(red.hosts())[-10]}]: ").strip() or str(list(red.hosts())[-10])
    dns = input("DNS (default 8.8.8.8,1.1.1.1): ").strip() or "8.8.8.8,1.1.1.1"

    # Configure interface in /etc/default/isc-dhcp-server
    print("[INFO] Configuring service interface...")
    with open(dhcp_iface_conf, "r") as f:
        lines = f.readlines()
    new_lines = []
    found = False
    for line in lines:
        if line.startswith("INTERFACESv4="):
            new_lines.append(f"INTERFACESv4=\"{iface_sel}\"\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"\nINTERFACESv4=\"{iface_sel}\"\n")
    with open(dhcp_iface_conf, "w") as f:
        f.writelines(new_lines)

    # Generate dhcpd.conf configuration
    print("[INFO] Writing DHCP configuration...")
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

    # Restart service
    print("[INFO] Restarting DHCP service...")
    run("systemctl enable isc-dhcp-server", check=False)
    run("systemctl restart isc-dhcp-server", check=False)

    status = run("systemctl is-active isc-dhcp-server", check=False)
    if "active" in status.stdout:
        print(f"[OK] DHCP active on interface {iface_sel}")
        print(f"[INFO] Range: {rango_ini} → {rango_fin}")
    else:
        print("[ERROR] DHCP could not start. Check with: journalctl -u isc-dhcp-server")

# ==============================
# CONFIG DNS
# ==============================

def configurar_dns(zona="", ip_servidor=""):
    """
    Configura un servidor DNS básico usando Bind9.
    - Crea zona directa y reversa
    - Define registros A y NS
    - Reinicia el servicio

    Args:
        zona (str): Dominio a gestionar
        ip_servidor (str): IP del servidor DNS
    """
    print("[INFO] Iniciando configuración del servidor DNS...")

    # Instalar bind9 si no está instalado
    subprocess.run("apt-get update -y && apt-get install -y bind9", shell=True, check=True)

    # Definir rutas
    named_conf_local = "/etc/bind/named.conf.local"
    zona_directa = f"/etc/bind/db.{zona}"
    zona_reversa = f"/etc/bind/db.{ip_servidor.split('.')[2]}.rev"

    # Crear configuración de zona directa y reversa
    zona_conf = f"""
zone "{zona}" {{
    type master;
    file "{zona_directa}";
}};
zone "{'.'.join(ip_servidor.split('.')[:3])}.in-addr.arpa" {{
    type master;
    file "{zona_reversa}";
}};
"""

    with open(named_conf_local, "a") as f:
        f.write(zona_conf)

    # Crear archivo de zona directa
    with open(zona_directa, "w") as f:
        f.write(f"""
$TTL    604800
@       IN      SOA     ns.{zona}. admin.{zona}. (
                        2         ; Serial
                        604800     ; Refresh
                        86400      ; Retry
                        2419200    ; Expire
                        604800 )   ; Negative Cache TTL
;
@       IN      NS      ns.{zona}.
ns      IN      A       {ip_servidor}
@       IN      A       {ip_servidor}
""")

    # Crear zona reversa
    ip_last = ip_servidor.split('.')[-1]
    with open(zona_reversa, "w") as f:
        f.write(f"""
$TTL    604800
@       IN      SOA     ns.{zona}. admin.{zona}. (
                        2
                        604800
                        86400
                        2419200
                        604800 )
;
@       IN      NS      ns.{zona}.
{ip_last}    IN      PTR     ns.{zona}.
""")

    # Reiniciar servicio
    subprocess.run("systemctl restart bind9 && systemctl enable bind9", shell=True, check=True)

    print("[OK] DNS configurado correctamente.")
    print(f"Zona: {zona} - Servidor: {ip_servidor}")

def actualizar_dns_local():
    """
    Sincroniza los registros DNS con los equipos descubiertos por UDP.
    - Envía broadcast solicitando nombres
    - Recibe payloads con formato 'IP?=HOSTNAME'
    - Actualiza cache local y zona DNS (bind9)
    """
    print("[INFO] Iniciando actualización dinámica del DNS local...")

    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    hosts_cache = {}

    # 1️⃣ Cargar cache existente
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    ip, host = line.split("=")
                    hosts_cache[ip] = host

    # 2️⃣ Enviar broadcast para solicitar nombres
    send_to_hosts("REQUEST_NAME")

    # 3️⃣ Escuchar respuestas UDP (formato IP?=HOSTNAME)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", UDP_PORT))
    sock.settimeout(5.0)

    try:
        while True:
            data, _ = sock.recvfrom(1024)
            payload = data.decode(errors="ignore").strip()
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\?=(\S+)", payload)
            if match:
                ip, host = match.groups()
                hosts_cache[ip] = host
                print(f"[DISCOVERED] {ip} -> {host}")
    except socket.timeout:
        pass
    finally:
        sock.close()

    # 4️⃣ Guardar cache actualizado
    with open(CACHE_FILE, "w") as f:
        for ip, host in hosts_cache.items():
            f.write(f"{ip}={host}\n")

    # 5️⃣ Actualizar archivo de zona DNS
    if not os.path.exists(DNS_FILE):
        print(f"[ERROR] Archivo de zona DNS no encontrado: {DNS_FILE}")
        return

    with open(DNS_FILE) as f:
        lines = f.readlines()

    # Filtrar registros A previos
    lines = [l for l in lines if not re.match(r"^\S+\s+IN\s+A\s+\d+\.\d+\.\d+\.\d+", l)]

    # Insertar nuevos registros A
    lines.append(f"; Actualización automática {datetime.now().isoformat()}\n")
    for ip, host in hosts_cache.items():
        lines.append(f"{host}\tIN\tA\t{ip}\n")

    # 6️⃣ Guardar y reiniciar servicio DNS
    with open(DNS_FILE, "w") as f:
        f.writelines(lines)

    subprocess.run("systemctl restart bind9", shell=True, check=False)
    print("[OK] DNS local actualizado y reiniciado correctamente.")


# ==============================
# COMMUNICATION FUNCTIONS
# ==============================

def send_to_hosts(payload, port=50000, timeout=2.0, send=True):
    """
    Discovers hosts on all internal interfaces defined globally and
    sends a UDP payload.

    Args:
        payload (str): Message to send to discovered hosts.
        port (int): UDP communication port.
        timeout (float): Maximum listen time per interface (s).
        send (bool): If True, sends the payload after discovering hosts.
    """
    import socket, struct, fcntl, time, uuid, json, os

    DISCOVER_MESSAGE_PREFIX = "DISCOVER_REQUEST"
    RESPONSE_PREFIX = "DISCOVER_RESPONSE"
    HOSTS_FILE = "hosts.json"

    # Assumes a global 'interfaces' dict defined from another function
    global interfaces
    internals = [iface for iface, v in interfaces.items() if v["type"] == "internal"]
    

    def get_broadcast(iface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8919,  # SIOCGIFBRDADDR
                struct.pack('256s', iface.encode('utf-8')[:15])
            )[20:24])
        except Exception as e:
            print(f"[net] Error getting broadcast for {iface}: {e}")
            return "255.255.255.255"

    def save_hosts(discovered):
        try:
            with open(HOSTS_FILE, "w") as f:
                json.dump(discovered, f, indent=2)
            print(f"[store] {len(discovered)} hosts saved in {HOSTS_FILE}")
        except Exception as e:
            print(f"[store] Error saving hosts: {e}")

    discovered_total = {}

    for iface in internals:
        broadcast_ip = get_broadcast(iface)
        print(f"[discover:{iface}] using broadcast {broadcast_ip}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)

        token = str(uuid.uuid4())[:8]
        discover_msg = f"{DISCOVER_MESSAGE_PREFIX}:{token}"
        sock.sendto(discover_msg.encode(), (broadcast_ip, port))
        print(f"[discover:{iface}] Broadcast sent, waiting {timeout}s...")

        start_time = time.time()
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                text = data.decode(errors="ignore")
                ip, _ = addr
                if text.startswith(RESPONSE_PREFIX):
                    parts = text.split(":", 2)
                    hostname = parts[1] if len(parts) > 1 else ip
                    nodeid = parts[2] if len(parts) > 2 else ""
                    discovered_total[ip] = {"hostname": hostname.strip(), "nodeid": nodeid.strip()}
                    print(f"[discover:{iface}] response from {ip} -> {hostname}")
            except socket.timeout:
                break
            if time.time() - start_time > timeout:
                break

    if not discovered_total:
        print("[discover] No listeners detected on internal interfaces.")
        return {}

    print(f"[discover] Total {len(discovered_total)} hosts found:")
    for ip, info in discovered_total.items():
        print(f"  - {ip} ({info.get('hostname')})")

    save_hosts(discovered_total)

    if send:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)  # Maximum wait time for response
        for ip in discovered_total.keys():
            try:
                sock.sendto(payload.encode(), (ip, port))
                print(f"[send] payload sent to {ip}")
                
                # Listen for response
                try:
                    data, addr = sock.recvfrom(1024)  # 1024 byte buffer
                    print(f"[recv] response from {addr[0]}: {data.decode(errors='ignore')}")
                except socket.timeout:
                    print(f"[recv] no response from {ip}")
                
            except Exception as e:
                print(f"[send] failed to send to {ip}: {e}")


    return discovered_total

def main():
    O = int(input(
        "\nSelect an option:\n"
        "1. DEBUG\n"
        "2. Configure SSH\n"
        "3. Configure DHCP\n"
        "4. configure nat\n"
        "5. configure DNS\n"
        "6. configure ftp\n"
        "7. configure https\n" 
        "8. configure mail\n"
        "9. update local-hosts\n"
        "10.update dns client list\n"
        "Option\n> "))
    

    match O:
        case 1:
            Z = int(input("\nSelect an option:\n"
                          "1. Test connection\n"
                          "2. test interfaces\n" 
                          "Option\n> "))
            match Z:
                case 1:
                    detect_interfaces()
                    send_to_hosts("test")
                case 2:
                    detect_interfaces()
                    print(interfaces)
                
        case 2:
            configure_ssh()
        case 3:
            detect_interfaces()
            configure_dhcp()
            send_to_hosts("config_dhcp")
        case 4:
            nat_configuration()
        case 5:
            zona = input("Enter the domain name (e.g., example.com): ").strip()
            ip_servidor = input("Enter the server IP address").strip()
            configurar_dns(zona="", ip_servidor="")
        case 6:
            print("coming soon")
        case 7:
            print("coming soon")
        case 8:
            print("coming soon")
        case 9:
            send_to_hosts("UPDATE_HOSTS")
        case 10:
            actualizar_dns_local()






    
if __name__ == "__main__":
    main()
'''
program writed by nkv also know as nkv-alex

 ^   ^
( o.o ) 
 > ^ <
 >cat<
'''
# copiable comments for program
# [INFO]
# [WARN]
# [ERROR]
# [STEP]
# [OK]
