import subprocess
import os

def run(cmd):
    """Ejecuta un comando en shell y muestra el resultado."""
    print(f"[INFO] Ejecutando: {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def uninstall_debug():
    run("apt remove -y gdb strace ltrace")
    run("apt autoremove -y")
    print("[OK] Entorno de depuración limpiado.")

def uninstall_ssh():
    run("systemctl stop ssh")
    run("apt purge -y openssh-server openssh-client")
    run("rm -rf /etc/ssh")
    print("[OK] SSH completamente eliminado.")

def uninstall_dhcp():
    run("systemctl stop isc-dhcp-server || true")
    run("apt purge -y isc-dhcp-server")
    run("rm -rf /etc/dhcp")
    print("[OK] DHCP purgado y limpiado.")

def uninstall_nat():
    run("iptables -F")
    run("iptables -t nat -F")
    run("apt purge -y iptables nftables")
    print("[OK] NAT y reglas iptables eliminadas.")

def uninstall_dns():
    run("systemctl stop bind9 || true")
    run("apt purge -y bind9 bind9utils bind9-doc")
    run("rm -rf /etc/bind")
    print("[OK] Servidor DNS eliminado.")

def uninstall_ftp():
    run("systemctl stop vsftpd || true")
    run("apt purge -y vsftpd")
    run("rm -rf /etc/vsftpd.conf /etc/vsftpd")
    print("[OK] Servidor FTP eliminado.")

def uninstall_https():
    run("systemctl stop apache2 || true")
    run("systemctl stop nginx || true")
    run("apt purge -y apache2 nginx certbot")
    run("rm -rf /etc/letsencrypt /var/www/html")
    print("[OK] Servidores HTTPS eliminados.")

def uninstall_mail():
    run("systemctl stop postfix dovecot || true")
    run("apt purge -y postfix dovecot-core dovecot-imapd")
    run("rm -rf /etc/postfix /etc/dovecot")
    print("[OK] Servicios de correo eliminados.")

def uninstall_local_hosts():
    run("rm -f /etc/hosts")
    print("[OK] Archivo local hosts eliminado (requiere regeneración).")

def uninstall_dns_clients():
    run("rm -rf /etc/resolv.conf /etc/systemd/resolved.conf")
    print("[OK] Configuración DNS cliente eliminada.")

def main():
    try:
        O = int(input(
            "\nSeleccione una opción para desinstalar:\n"
            "1. DEBUG\n"
            "2. SSH\n"
            "3. DHCP\n"
            "4. NAT\n"
            "5. DNS\n"
            "6. FTP\n"
            "7. HTTPS\n"
            "8. MAIL\n"
            "9. local-hosts\n"
            "10. dns client list\n"
            "> "
        ))
    except ValueError:
        print("[ERROR] Entrada no válida.")
        return

    os.system("clear")
    print("[INFO] Iniciando desinstalación...")

    match O:
        case 1: uninstall_debug()
        case 2: uninstall_ssh()
        case 3: uninstall_dhcp()
        case 4: uninstall_nat()
        case 5: uninstall_dns()
        case 6: uninstall_ftp()
        case 7: uninstall_https()
        case 8: uninstall_mail()
        case 9: uninstall_local_hosts()
        case 10: uninstall_dns_clients()
        case _: print("[ERROR] Opción no válida.")

    print("\n[FINALIZADO] Operación completada con éxito.\n")

if __name__ == "__main__":
    main()
