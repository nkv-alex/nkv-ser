#!/usr/bin/env python3
# conf-serv.py
# Script for Ubuntu 22.04 or Debian 12: add services to the server .

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
LOG_PATH = "./res.log"
LOG_ACTIVE = False

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


class Logger:
    def __init__(self, logfile=LOG_PATH):
        os.makedirs(os.path.dirname(logfile), exist_ok=True)
        self.logfile = logfile
        self.terminal = sys.stdout
        self.log = open(logfile, "a", buffering=1)  # auto flush

    def write(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.terminal.write(message)
        self.log.write(line)

    def flush(self):
        pass  # requerido por sys.stdout

class log:
    """Context manager para redirigir stdout y stderr."""
    def __enter__(self):
        self.logger = Logger()
        sys.stdout = self.logger
        sys.stderr = self.logger
        print(f"=== LOG SESSION START {datetime.now()} ===\n")
        return self.logger

    def __exit__(self, exc_type, exc_value, traceback):
        print(f"\n=== LOG SESSION END {datetime.now()} ===\n")
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        self.logger.log.close()

# ==============================
# CONFIG NAT
# ==============================

def detect_interfaces():

    """Detect interfaces and saves it in a json.
    """
    global interfaces

    
    # Load existing JSON
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
    
    

    #Detect interfaces 
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

    #Process detected interfaces
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

    #Save changes if there were updates
    if updated:
        try:
            with open(JSON_FILE, "w") as f:
                json.dump(interfaces, f, indent=4)
            print(f"[INFO] Configuration updated in {JSON_FILE}")
        except Exception as e:
            print(f"[ERROR] Could not save {JSON_FILE}: {e}")
    else:
        print("[INFO] No changes in interfaces.")

    #Show summary
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
            # Do not force external gateway
            # Keep any previous config
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
    asking = input("Do you want to try to enable iptables-persistent for rule persistence? (y/n) [y]: ").strip().lower()
    if asking == "y":
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

    if LOG_ACTIVE == True:
        log()

    print("Automatic NAT configuration Ubuntu 22.04")
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
    print("Custom SSH configuration")

    config_path = "/etc/ssh/sshd_config"
    backup_path = f"{config_path}.bak"

    if LOG_ACTIVE == True:
        log()

    # Backup
    if not os.path.exists(backup_path):
        print(f"[INFO] Generating backup: {backup_path}")
        run(f"sudo cp {config_path} {backup_path}")
    else:
        print(f"[INFO] Existing backup: {backup_path}")

    # Requested parameters
    print("\n=== SSH parameters ===")
    puerto = input("SSH port (default 22): ").strip() or "22"
    root_login = input("Allow root login? (yes/no) [no]: ").strip().lower() or "no"

    #  User detection
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

    #  Read the file
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

    # Apply key parameters
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

    # Save
    tmp_file = "/tmp/sshd_config_tmp"
    with open(tmp_file, "w") as f:
        f.writelines(lines)

    run(f"sudo mv {tmp_file} {config_path}")
    run("sudo chmod 600 /etc/ssh/sshd_config")

    # Reiniciar servicio
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
    print(" Automatic DHCP configuration (isc-dhcp-server) ")

    if LOG_ACTIVE == True:
        log()


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
    res = input("Is isc-dhcp-server installed? (y/n) [y]: ").strip().lower() or "y"
    if res == "y":
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

    lease_time = input("Default lease time (seconds) [600]: ").strip() or "600"
    max_lease_time = input("Max lease time (seconds) [7200]: ").strip() or "7200"


    # Generate dhcpd.conf configuration
    print("[INFO] Writing DHCP configuration...")
    dhcp_config = f"""
        # Generated by conf-serv.py
        default-lease-time {lease_time};
        max-lease-time {max_lease_time};
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


def update_dhcp_client_list():    
    if LOG_ACTIVE == True:
        log()

print("[INFO] Updating DHCP client list from leases...")

# ==============================
# CONFIG FTP
# ==============================
def configure_ftp():
    run("clear")
    print("=== Automatic FTP configuration (vsftpd) ===")
    
    # --- INSTALLATION BLOCK ---
    res = input("Is vsftpd installed? (y/n) [n]: ").strip().lower() or "n"
    if res == "n":
        run("apt update -y", check=False)
        run("apt install -y vsftpd", check=False)

    if LOG_ACTIVE:
        log()

    conf = "/etc/vsftpd.conf"
    backup_file(conf)

    # --- ASK USER FOR FTP ROOT PATH ---
    default_path = "/home/$USER/ftp"
    custom_path = input(f"Enter FTP root directory [{default_path}]: ").strip()
    if not custom_path:
        custom_path = default_path

    # --- CREATE DIRECTORY IF NOT EXISTS ---
    expanded_path = os.path.expandvars(custom_path)
    expanded_path = os.path.expanduser(expanded_path)
    os.makedirs(expanded_path, exist_ok=True)

    user = os.getenv("SUDO_USER") or os.getenv("USER") or "ftpuser"
    os.system(f"chown -R {user}:{user} '{expanded_path}'")
    os.system(f"chmod 755 '{expanded_path}'")

    print(f"[OK] FTP directory ready at {expanded_path}")

    # --- MODIFY CONFIGURATION ---
    print("\n[STEP] Customizing vsftpd configuration...")
    with open(conf, "r") as f:
        lines = f.readlines()

    def set_param(param, value):
        found = False
        for i, l in enumerate(lines):
            if l.strip().startswith(param):
                lines[i] = f"{param}={value}\n"
                found = True
                break
        if not found:
            lines.append(f"{param}={value}\n")

    set_param("anonymous_enable", "NO")
    set_param("local_enable", "YES")
    set_param("write_enable", "YES")
    set_param("chroot_local_user", "YES")
    set_param("allow_writeable_chroot", "YES")
    set_param("listen", "YES")
    set_param("listen_ipv6", "NO")
    set_param("pam_service_name", "vsftpd")
    set_param("user_sub_token", "$USER")
    set_param("local_root", custom_path)

    with open(conf, "w") as f:
        f.writelines(lines)

    # --- RESTART SERVICE ---
    print("[INFO] Restarting FTP service...")
    run("systemctl enable vsftpd", check=False)
    run("systemctl restart vsftpd", check=False)

    status = run("systemctl is-active vsftpd", check=False)
    if "active" in getattr(status, "stdout", ""):
        print("[OK] FTP service running successfully.")
        print(f"[INFO] Users will connect to: {expanded_path}")
    else:
        print("[ERROR] FTP failed to start. Check journalctl -u vsftpd.")

# ==============================
# CONFIG HTTPS
# ==============================
def configure_https():
    print("=== Automatic HTTPS configuration (Apache2 + SSL) ===")

    # Instalar Apache2 + OpenSSL si no existe
    res = input("Is Apache2 installed? (y/n) [n]: ").strip().lower() or "n"
    if res == "n":
        run("apt update -y && apt install -y apache2 openssl ufw", check=False)

    if LOG_ACTIVE:
        log()

    site_conf = "/etc/apache2/sites-available/default-ssl.conf"
    backup_file(site_conf)

    # Detectar IP del servidor automáticamente
    ip = input("Enter server IP for HTTPS [auto-detect]: ").strip()
    if not ip:
        # detecta la IP principal
        ip = os.popen("hostname -I | awk '{print $1}'").read().strip()
        print(f"[INFO] Using detected IP: {ip}")

    cert_dir = "/etc/ssl/localcerts"
    os.makedirs(cert_dir, exist_ok=True)

    key_file = f"{cert_dir}/{ip}.key"
    crt_file = f"{cert_dir}/{ip}.crt"

    print("[STEP] Generating self-signed certificate for IP...")
    run(f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
        f"-keyout {key_file} -out {crt_file} "
        f"-subj '/CN={ip}'", check=False)

    os.chmod(key_file, 0o600)
    os.chmod(crt_file, 0o644)

    # Habilitar SSL en Apache y sitio default-ssl
    run("a2enmod ssl", check=False)
    run("a2ensite default-ssl", check=False)

    # Actualizar VirtualHost con IP
    with open(site_conf, "r") as f:
        data = f.read()

    # Modifica ServerName
    if re.search(r"ServerName\s+.*", data):
        data = re.sub(r"ServerName\s+.*", f"ServerName {ip}", data)
    else:
        data = data.replace("</VirtualHost>", f"    ServerName {ip}\n</VirtualHost>")

    # Modifica rutas de certificado
    data = re.sub(r"SSLCertificateFile\s+.*", f"SSLCertificateFile {crt_file}", data)
    data = re.sub(r"SSLCertificateKeyFile\s+.*", f"SSLCertificateKeyFile {key_file}", data)

    with open(site_conf, "w") as f:
        f.write(data)

    # Abrir puerto 443 en firewall si UFW activo
    run("ufw allow 443/tcp", check=False)
    run("ufw reload", check=False)

    # Reiniciar Apache
    run("systemctl restart apache2", check=False)
    status = run("systemctl is-active apache2", check=False)

    if "active" in getattr(status, "stdout", ""):
        print(f"[OK] HTTPS active → https://{ip}")
    else:
        print("[ERROR] Apache failed to start. Check logs in /var/log/apache2/")
# ==============================
# CONFIG MAIL
# ==============================
def configure_mail():
    print("=== Automatic Mail configuration (Postfix) ===")

    res = input("Is Postfix installed? (y/n) [n]: ").strip().lower() or "n"
    if res == "n":
        # Preconfigurar Postfix para no interactuar
        run("echo 'postfix postfix/mailname string empresa.local' | debconf-set-selections", check=False)
        run("echo 'postfix postfix/main_mailer_type string 'Internet Site'' | debconf-set-selections", check=False)
        run("apt update -y && DEBIAN_FRONTEND=noninteractive apt install -y postfix mailutils", check=False)


    if LOG_ACTIVE == True:
        log()

    domain = input("Enter mail domain [default empresa.local]: ").strip() or "empresa.local"
    relay = input("Relay host (empty = none): ").strip()

    main_cf = "/etc/postfix/main.cf"
    backup_file(main_cf)

    cfg = [
        "myhostname = mail." + domain,
        "myorigin = /etc/mailname",
        "mydestination = $myhostname, localhost.$mydomain, localhost",
        "relayhost = " + (relay if relay else ""),
        "mynetworks = 127.0.0.0/8",
        "inet_interfaces = all",
        "inet_protocols = ipv4",
        "home_mailbox = Maildir/"
    ]

    with open(main_cf, "w") as f:
        f.write("\n".join(cfg) + "\n")

    run(f"echo {domain} > /etc/mailname", check=False)
    run("systemctl enable postfix && systemctl restart postfix", check=False)

    status = run("systemctl is-active postfix", check=False)
    if "active" in status.stdout:
        print(f"[OK] Mail service ready for domain {domain}")
    else:
        print("[ERROR] Postfix could not start. Check logs in /var/log/mail.log")

# ==============================
# CONFIG SAMBA
# ==============================
def config_samba():
    print("=== Automatic SAMBA configuration ===")

    if LOG_ACTIVE:
        log()

    # Instalación de paquetes
    res = input("Is Samba installed? (y/n) [n]: ").strip().lower() or "n"
    if res == "n":
        print("[INFO] Installing Samba packages...")
        run("apt update -y", check=False)
        run("apt install -y samba", check=False)

    smb_conf = "/etc/samba/smb.conf"
    backup_file(smb_conf)

    # Directorio compartido
    default_share = "/srv/samba/shared"
    shared_dir = input(f"Enter shared directory [{default_share}]: ").strip() or default_share
    os.makedirs(shared_dir, exist_ok=True)

    # Permisos
    os.system(f"chmod 2770 '{shared_dir}'")
    os.system(f"chown root:sambashare '{shared_dir}'")

    # Usuario Samba
    print("\n[STEP] Samba user configuration:")
    user = input("Enter user to grant Samba access [default current user]: ").strip() or os.getenv("SUDO_USER") or os.getenv("USER")
    run(f"id -u {user} >/dev/null 2>&1 || useradd -m {user}", check=False)
    print(f"[INFO] Setting Samba password for user '{user}'")
    os.system(f"smbpasswd -a {user}")

    # Crear grupo si no existe
    run("getent group sambashare || groupadd sambashare", check=False)
    run(f"usermod -aG sambashare {user}", check=False)

    # Modificar configuración smb.conf
    print("[INFO] Updating smb.conf ...")
    with open(smb_conf, "r") as f:
        data = f.read()

    Ron = input("Read only? (yes/no) [no]: ").strip().lower() or "no"
    Guest = input("Allow guests? (yes/no) [no]: ").strip().lower() or "no"
    brawseable = input("Brawseable? (yes/no) [no]: ").strip().lower() or "no"

    if "[shared]" not in data:
        data += f"""
    [shared]
    path = {shared_dir}
    browseable = {brawseable}
    read only = {Ron}
    guest ok = {Guest}
    valid users = @{user}
    force group = sambashare
    create mask = 0660
    directory mask = 2770
    """
    with open(smb_conf, "w") as f:
        f.write(data)

    # Reiniciar servicio
    print("[INFO] Restarting Samba service...")
    run("systemctl enable smbd nmbd", check=False)
    run("systemctl restart smbd nmbd", check=False)

    status = run("systemctl is-active smbd", check=False)
    if "active" in status.stdout:
        print(f"[OK] Samba active. Shared folder: {shared_dir}")
        print(f"[INFO] Access from Windows via: \\\\{os.popen('hostname -I | awk \"{print $1}\"').read().strip()}\\shared")
    else:
        print("[ERROR] Samba service could not start. Check logs with: journalctl -u smbd")

# ==============================
# CONFIG NFS
# ==============================
def configure_nfs():
    print("=== Automatic NFS configuration (Network File System) ===")
    
    # Instalación de paquetes
    res = input("Is NFS server installed? (y/n) [n]: ").strip().lower() or "n"
    if res == "n":
        print("[INFO] Installing NFS server packages...")
        run("apt update -y && apt install -y nfs-kernel-server portmap", check=False)

    if LOG_ACTIVE == True:
        log()

    exports = "/etc/exports"
    backup_file(exports)

    # Parámetros de configuración
    print("\n[STEP] Gathering configuration parameters...")
    share_name = input("Name of the NFS shared folder [default shared]: ").strip() or "shared"
    
    path = input("Add the path for the shared folder (default = /srv/nfs/) :" ).strip() or "/srv/nfs/"
    share_path = f"{path}{share_name}"
    subnet = input("Allowed subnet (e.g. 192.168.1.0/24) [default 192.168.1.0/24]: ").strip() or "192.168.1.0/24"
    readonly = input("Read only? (y/n) [n]: ").strip().lower() or "n"
    no_subtr_chk = input("subtree check? (y/n) [n]: ").strip().lower() or "n"
    # Crear carpeta y permisos
    os.makedirs(share_path, exist_ok=True)
    run(f"chmod -R 777 {share_path}", check=False)

    print("[STEP] Updating exports configuration...")
    try:
        with open(exports, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    # Eliminar entradas previas con la misma ruta
    lines = [l for l in lines if not l.startswith(share_path)]

    if readonly == "y" and no_subtr_chk == "y":
        export_opts = "ro,sync,no_subtree_check"
    elif readonly == "y" and no_subtr_chk == "n":
        export_opts = "ro,sync,subtree_check"
    elif readonly == "n" and no_subtr_chk == "y":
        export_opts = "rw,sync,no_subtree_check"
    else:
        export_opts = "rw,sync,subtree_check"



    lines.append(f"{share_path} {subnet}({export_opts})\n")

    with open(exports, "w") as f:
        f.writelines(lines)

    # Aplicar configuración
    print("[INFO] Applying export configuration...")
    run("exportfs -ra", check=False)
    run("systemctl enable nfs-kernel-server", check=False)
    run("systemctl restart nfs-kernel-server", check=False)

    status = run("systemctl is-active nfs-kernel-server", check=False)

    #kurva = input("Is Automount and make permanent in users? (y/n) [n]: ").strip().lower() or "n"
    
    #if kurva = "y"
 #send_to_hosts("mount {share_path}")

    if "active" in status.stdout:
        print(f"[OK] NFS server running successfully.")
        print(f"[INFO] Shared path: {share_path}")
        print(f"[INFO] Allowed subnet: {subnet}")
        print(f"[INFO] Mount example (client): mount {run('hostname -I | awk {print $1}', check=False).stdout.strip()}:{share_path} /mnt")
    else:
        print("[ERROR] NFS service failed to start. Check journalctl -u nfs-kernel-server.")

# ==============================
# CONFIG DNS
# ==============================

def autoconfig_dns():
    
    print("=== Automatic DNS configuration (dnsmasq) ===")

    if LOG_ACTIVE:
        log()

    # --- PREPARACIÓN ---
    conf_path = "/etc/dnsmasq.conf"
    hosts_path = "/etc/hosts"
    backup_file(conf_path)

    res = input("Is dnsmasq installed? (y/n) [n]: ").strip().lower() or "n"
    if res == "n":
        print("[INFO] Installing dnsmasq...")
        run("apt update -y", check=False)
        run("apt install -y dnsmasq", check=False)

    # --- CARGA DE INTERFACES ---
    if not os.path.exists("interfaces.json"):
        print("[ERROR] interfaces.json not found. Run NAT configuration first.")
        return
    with open("interfaces.json", "r") as f:
        interfaces = json.load(f)

    internal_ifaces = [k for k, v in interfaces.items() if v["type"] == "internal"]
    if not internal_ifaces:
        print("[ERROR] No internal interfaces found.")
        return

    iface = internal_ifaces[0]
    print(f"[INFO] Using internal interface: {iface}")

    # --- PARÁMETROS DNS ---
    domain = input("Local domain name [empresa.local]: ").strip() or "empresa.local"
    dns_range = input("Upstream DNS (comma-separated) [8.8.8.8,1.1.1.1]: ").strip() or "8.8.8.8,1.1.1.1"

    # --- CONFIGURACIÓN ---
    print("[INFO] Writing dnsmasq configuration...")
    conf_data = f"""
    # Generated by conf-serv.py
    domain={domain}
    interface={iface}
    listen-address=127.0.0.1
    listen-address={interfaces[iface]['ip'].split('/')[0]}
    bind-interfaces
    expand-hosts
    domain-needed
    bogus-priv
    no-resolv
    server={dns_range.replace(',', '\\nserver=')}
    """.strip()

    with open(conf_path, "w") as f:
        f.write(conf_data + "\n")

    # --- REINICIO DEL SERVICIO ---
    print("[INFO] Restarting dnsmasq service...")
    run("systemctl enable dnsmasq", check=False)
    run("systemctl restart dnsmasq", check=False)

    status = run("systemctl is-active dnsmasq", check=False)
    if "active" in status.stdout:
        print(f"[OK] dnsmasq active on {iface} with domain '{domain}'")
        print(f"[INFO] Config path: {conf_path}")
    else:
        print("[ERROR] dnsmasq failed to start. Check logs with: journalctl -u dnsmasq")

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
        print("[discover] No listeners detected.")
        return {}

    print(f"[discover] Total {len(discovered_total)} hosts found:")
    for ip, info in discovered_total.items():
        print(f"  - {ip} ({info.get('hostname')})")

    save_hosts(discovered_total)

    if send:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)  
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



# ==============================
# MAIN
# ==============================


def main():
    global interfaces, LOG_ACTIVE
    while True:
        try:
            O = int(input(
                "\nSelect an option:\n"
                "1. DEBUG\n"
                "2. Configure SSH\n"
                "3. Configure DHCP\n"
                "4. configure nat\n"
                "5. configure ftp\n"
                "6. configure https\n"
                "7. configure mail\n"
                "8. configure samba\n"
                "9. Configure NFS\n"
                "10. Configure DNS\n"
                "Option\n> "))
        

            match O:
                case 1:
                    Z = int(input("\nSelect an option:\n"
                                "1. Test connection\n"
                                "2. test interfaces\n"
                                "3. activate logs\n"
                                "4. update dhcp client list\n"
                                "5. update local-hosts\n"
                                "Option\n> "))
                    match Z:
                        case 1:
                            detect_interfaces()
                            send_to_hosts("test")
                        case 2:
                            detect_interfaces()
                            print(interfaces)
                        case 3:
                            LOG_ACTIVE = True
                            print("[INFO] Logging activated.")
                        case 4:
                            update_dhcp_client_list()
                        case 5:
                            send_to_hosts("UPDATE_HOSTS")
                case 2:
                    configure_ssh()
                case 3:
                    detect_interfaces()
                    configure_dhcp()
                    send_to_hosts("config_dhcp")
                case 4:
                    nat_configuration()
                case 5:
                    configure_ftp()
                case 6:
                    configure_https()
                case 7:
                    configure_mail()
                case 8:
                    config_samba()
                case 9:
                    run("clear")
                    configure_nfs()
                    
                case 10:
                    autoconfig_dns()
                case _:
                    print("Invalid option.")

        except KeyboardInterrupt:
            print("\nExiting...")
            break





    
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
