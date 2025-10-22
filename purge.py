#!/usr/bin/env python3
# uninstall-serv.py
# Desinstalador automático de servicios configurados por conf-serv.py

import subprocess
import os
import sys

# ==============================
# Os Functions
# ==============================

def run(cmd, fatal=False):
    """Ejecuta un comando shell con logging estandarizado."""
    print(f"[INFO] Ejecutando: {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[WARN] Error ejecutando comando: {res.stderr.strip()}")
        if fatal:
            print("[ERROR] Ejecución abortada.")
            sys.exit(1)
    return res


def check_root():
    """Valida que el script se ejecute como root."""
    if os.geteuid() != 0:
        print("[ERROR] Debes ejecutar este script como root (sudo).")
        sys.exit(1)


# ==============================
# Uninstall Functions
# ==============================

def uninstall_ssh():
    run("systemctl stop ssh || true")
    run("apt purge -y openssh-server openssh-client")
    run("rm -rf /etc/ssh /var/run/sshd")
    print("[OK] SSH completamente eliminado.")

def uninstall_dhcp():
    run("systemctl stop isc-dhcp-server || true")
    run("apt purge -y isc-dhcp-server")
    run("rm -rf /etc/dhcp /var/lib/dhcp")
    print("[OK] DHCP purgado y limpiado.")

def uninstall_nat():
    run("iptables -F || true")
    run("iptables -t nat -F || true")
    run("apt purge -y iptables nftables")
    run("rm -rf /etc/iptables /etc/netplan/backups_nat_helper")
    print("[OK] NAT y reglas iptables eliminadas.")

def uninstall_dns():
    run("systemctl stop bind9 || true")
    run("apt purge -y bind9 bind9utils bind9-doc")
    run("rm -rf /etc/bind /var/lib/bind")
    print("[OK] Servidor DNS eliminado.")

def uninstall_ftp():
    run("systemctl stop vsftpd || true")
    run("apt purge -y vsftpd")
    run("rm -rf /etc/vsftpd.conf /etc/vsftpd /var/ftp /srv/ftp")
    print("[OK] Servidor FTP eliminado.")

def uninstall_https():
    run("systemctl stop apache2 nginx || true")
    run("apt purge -y apache2 nginx certbot")
    run("rm -rf /etc/apache2 /etc/nginx /etc/letsencrypt /var/www/html")
    print("[OK] Servidores HTTPS eliminados.")

def uninstall_mail():
    run("systemctl stop postfix dovecot || true")
    run("apt purge -y postfix dovecot-core dovecot-imapd")
    run("rm -rf /etc/postfix /etc/dovecot /var/mail /var/spool/mail")
    print("[OK] Servicios de correo eliminados.")

def uninstall_samba():
    run("systemctl stop smbd nmbd || true")
    run("apt purge -y samba samba-common samba-common-bin")
    run("rm -rf /etc/samba /var/lib/samba /srv/samba")
    print("[OK] Samba eliminado correctamente.")

def uninstall_nfs():
    run("systemctl stop nfs-kernel-server || true")
    run("apt purge -y nfs-kernel-server nfs-common rpcbind")
    run("rm -rf /etc/exports /srv/nfs /var/lib/nfs")
    print("[OK] NFS eliminado correctamente.")

def uninstall_local_hosts():
    if os.path.exists("/etc/hosts"):
        run("rm -f /etc/hosts")
        run("cp /usr/share/base-files/hosts /etc/hosts || echo '127.0.0.1 localhost' > /etc/hosts")
        print("[OK] Archivo /etc/hosts restaurado.")
    else:
        print("[WARN] /etc/hosts no existe. No se requiere acción.")

def uninstall_dns_clients():
    run("rm -rf /etc/resolv.conf /etc/systemd/resolved.conf || true")
    print("[OK] Configuración DNS cliente eliminada.")

def full_purge():
    """Desinstalación masiva de todos los servicios."""
    print("[STEP] Ejecutando purga completa del entorno...")
    uninstall_ssh()
    uninstall_dhcp()
    uninstall_nat()
    uninstall_dns()
    uninstall_ftp()
    uninstall_https()
    uninstall_mail()
    uninstall_samba()
    uninstall_nfs()
    print("[OK] Todos los servicios fueron eliminados correctamente.")


# ==============================
# MENÚ PRINCIPAL
# ==============================

def main():
    check_root()

    try:
        O = int(input(
            "\nSeleccione una opción para desinstalar:\n"
            "1. salir\n"
            "2. SSH\n"
            "3. DHCP\n"
            "4. NAT\n"
            "5. DNS\n"
            "6. FTP\n"
            "7. HTTPS\n"
            "8. MAIL\n"
            "9. SAMBA\n"
            "10. NFS\n"
            "11. local-hosts\n"
            "12. dns client list\n"
            "13. purga completa\n"
            "> "
        ))
    except ValueError:
        print("[ERROR] Entrada no válida.")
        return

    os.system("clear")
    print("[INFO] Iniciando proceso de desinstalación...\n")

    match O:
        case 1: print("Saliendo del programa.")
        case 2: uninstall_ssh()
        case 3: uninstall_dhcp()
        case 4: uninstall_nat()
        case 5: uninstall_dns()
        case 6: uninstall_ftp()
        case 7: uninstall_https()
        case 8: uninstall_mail()
        case 9: uninstall_samba()
        case 10: uninstall_nfs()
        case 11: uninstall_local_hosts()
        case 12: uninstall_dns_clients()
        case 13: full_purge()
        case _: print("[ERROR] Opción no válida.")

    print("\n[FINALIZADO] Operación completada con éxito.\n")


if __name__ == "__main__":
    main()
