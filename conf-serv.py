#!/usr/bin/env python3
"""
conf-serv.py - Configuración NAT automática Ubuntu 22.04
- Detecta interfaces y sus IPs
- Genera / modifica /etc/netplan/01-nat.yaml (dhcp4: no)
- Habilita IP forwarding
- Genera reglas NAT iptables
- Guarda reglas en /etc/iptables/rules.v4 para iptables-persistent
"""

import os
import subprocess
import shutil
from datetime import datetime
import ipaddress
import yaml

NETPLAN_FILE = "/etc/netplan/01-nat.yaml"
BACKUP_DIR = "/etc/netplan/backups_nat_helper"
IPTABLES_RULES_V4 = "/etc/iptables/rules.v4"
SYSCTL_CONF = "/etc/sysctl.conf"

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
    """Detecta interfaces con IPs y pregunta si son internas o externas"""
    result = run("ip -o -4 addr show | awk '{print $2,$4}' | grep -v 'lo' | grep -v 'docker'", check=True)
    internals = {}
    externals = {}

    if not result.stdout.strip():
        print("[ERROR] No se encontraron interfaces con IP asignada.")
        return internals, externals

    print("\n=== Detección de interfaces ===")
    for line in result.stdout.strip().splitlines():
        iface, addr = line.split()
        ip = ipaddress.IPv4Interface(addr)
        print(f"\nInterfaz detectada: {iface}")
        print(f"Dirección IP: {ip}")
        tipo = input("¿Esta interfaz es interna (i) o externa (e)? [i/e]: ").strip().lower()

        if tipo == "e":
            externals[iface] = str(ip)
        else:
            internals[iface] = str(ip)

    print("\nResumen de selección:")
    print(f"  Internas: {list(internals.keys())}")
    print(f"  Externas: {list(externals.keys())}")

    return internals, externals


def build_netplan_yaml(existing_yaml, interfaces):
    """
    Modifica o crea el netplan existente, asignando:
      - dhcp4: yes en interfaces externas
      - dhcp4: no + address + nameservers + optional routes en internas
    """
    if "network" not in existing_yaml:
        existing_yaml["network"] = {"version": 2, "renderer": "networkd", "ethernets": {}}
    if "ethernets" not in existing_yaml["network"]:
        existing_yaml["network"]["ethernets"] = {}

    for iface, data in interfaces.items():
        ip = data.get("ip")
        tipo = data.get("type")  # 'internal' o 'external'
        iface_data = existing_yaml["network"]["ethernets"].get(iface, {})

        if tipo == "external":
            iface_data["dhcp4"] = True
            iface_data["optional"] = True
        else:
            iface_data["dhcp4"] = False
            iface_data["addresses"] = [ip]
            iface_data["nameservers"] = {"addresses": ["8.8.8.8", "1.1.1.1"]}
            # Si quieres gateway opcional interno:
            iface_data["routes"] = [{
                "to": "default",
                "via": str(ipaddress.IPv4Interface(ip).ip)
            }]

        existing_yaml["network"]["ethernets"][iface] = iface_data

    return existing_yaml



def write_netplan_file(yaml_text):
    """
    Modifica el archivo netplan existente sin perder otras configuraciones.
    """
    # Buscar un archivo netplan existente en /etc/netplan
    netplan_files = [f for f in os.listdir("/etc/netplan") if f.endswith(".yaml") or f.endswith(".yml")]
    if not netplan_files:
        print("[ERROR] No se encontró ningún archivo YAML en /etc/netplan/")
        return

    path = f"/etc/netplan/{netplan_files[0]}"
    backup_file(path)
    print(f"[INFO] Modificando {path}")

    # Leer YAML existente
    with open(path, "r") as f:
        try:
            existing_yaml = yaml.safe_load(f) or {}
        except yaml.YAMLError:
            print("[WARN] No se pudo parsear YAML existente, se sobrescribirá.")
            existing_yaml = {}

    # Modificar estructura con las IPs actuales
    modified_yaml = build_netplan_yaml(existing_yaml, interfaces)

    # Escribir YAML actualizado
    with open(path, "w") as f:
        yaml.dump(modified_yaml, f, default_flow_style=False, sort_keys=False)
    print(f"[INFO] Netplan actualizado con interfaces detectadas -> {path}")

def enable_ip_forwarding():
    backup_file(SYSCTL_CONF)
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
    run("sysctl -p", check=False)
    print("[INFO] IP forwarding habilitado")

def build_iptables_rules(internals, externals):
    lines = ["*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]",
             ":OUTPUT ACCEPT [0:0]", ":POSTROUTING ACCEPT [0:0]"]
    for ext in externals:
        for intf in internals:
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
    except:
        print("[WARN] iptables-restore falló, revisa las reglas manualmente")
    print(f"[INFO] Reglas iptables guardadas en {IPTABLES_RULES_V4}")

def try_enable_persistent():
    try:
        run("which apt >/dev/null 2>&1", check=True)
        run("DEBIAN_FRONTEND=noninteractive apt-get update -y", check=False)
        run("DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent", check=False)
        run("systemctl enable netfilter-persistent.service", check=False)
        run("systemctl restart netfilter-persistent.service", check=False)
    except:
        print("[WARN] No se pudo habilitar iptables-persistent automáticamente")

def apply_netplan():
    try:
        run("netplan apply", check=True)
        print("[INFO] Netplan aplicado")
    except:
        print("[WARN] netplan apply falló, revisa manualmente")

def main():
    if os.geteuid() != 0:
        print("Ejecuta este script con sudo/root")
        return
    print("=== Configuración NAT automática Ubuntu -serv ===")
    internals, externals = detect_interfaces()
    print(f"[INFO] Internas detectadas: {list(internals.keys())}")
    print(f"[INFO] Externas detectadas: {list(externals.keys())}")
    if not externals:
        print("[ERROR] No se detectaron interfaces externas. abortando.")
        return
    # Construir netplan
    all_ifaces = {**internals, **externals}
    yaml_text = build_netplan_yaml(all_ifaces)
    write_netplan_file(yaml_text)
    # Habilitar IP forwarding
    enable_ip_forwarding()
    # Generar iptables
    rules_text = build_iptables_rules(list(internals.keys()), list(externals.keys()))
    save_iptables_rules(rules_text)
    # Intentar persistencia
    try_enable_persistent()
    # Aplicar netplan
    apply_netplan()
    print("[FIN] Configuración NAT completada")

if __name__ == "__main__":
    main()
