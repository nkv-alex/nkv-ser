#!/usr/bin/env python3
import os
import subprocess
import json
import json
# ==============================
# System Utilities
# ==============================

def ejecutar(cmd):
    """Execute system command and return status."""
    try:
        print(f"[EXEC] {cmd}")
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {e}")
        return False

def formatear_discos():
    """Full wipe + uniform GPT partitioning and filesystem formatting across multiple disks."""
    print("[INFO] Starting full disk reinitialization and uniform formatting routine...")

    discos = input("Enter devices to format (e.g., /dev/sdb /dev/sdc /dev/sdd): ").split()
    if not discos:
        print("[WARN] No disks provided.")
        return

    tamanos = {}
    for disco in discos:
        try:
            cmd = f"lsblk -b -dn -o SIZE {disco}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                tamanos[disco] = int(res.stdout.strip())
            else:
                print(f"[ERROR] Could not read size of {disco}")
        except Exception as e:
            print(f"[ERROR] {disco}: {e}")

    if not tamanos:
        print("[ERROR] Could not determine any disk size.")
        return

    print("\nDetected disk sizes:")
    for d, sz in tamanos.items():
        print(f"  {d}: {sz / (1024**3):.2f} GB")

    disco_min = min(tamanos, key=tamanos.get)
    min_gb = tamanos[disco_min] / (1024**3)
    print(f"\n[INFO] Smallest disk: {disco_min} ({min_gb:.2f} GB)")

    tamaño_input = input(f"Enter partition size (<= {min_gb:.2f}GB, e.g., 25GB or 500MB): ").upper().strip()

    if tamaño_input.endswith("GB"):
        tamaño_bytes = float(tamaño_input[:-2]) * (1024**3)
    elif tamaño_input.endswith("MB"):
        tamaño_bytes = float(tamaño_input[:-2]) * (1024**2)
    else:
        print("[ERROR] Invalid size format. Use GB or MB suffix.")
        return

    if tamaño_bytes > tamanos[disco_min]:
        print("[ERROR] Size exceeds smallest disk capacity.")
        return

    tipo_fs = input("Enter filesystem type (e.g., ext4, xfs, btrfs): ").strip()

    print("\n[INFO] Starting complete wipe and partitioning...\n")

    for disco in discos:
        print(f"[TASK] Processing {disco}...")

        # ================================================
        # Desmontar cualquier filesystem
        # ================================================
        print("[STEP] Unmounting all filesystems on this disk...")
        ejecutar(f"lsblk -ln -o MOUNTPOINT {disco} | grep -v '^$' | xargs -r -n1 umount -f || true")

        # ================================================
        # Eliminar mappings activos del kernel (LVM)
        # ================================================
        print("[STEP] Removing any device mapper entries...")
        ejecutar(f"dmsetup remove -f {disco}* || true")

        # ================================================
        # Eliminar Logical Volumes
        # ================================================
        print("[STEP] Removing all Logical Volumes on this disk...")
        ejecutar("lvdisplay --colon 2>/dev/null | cut -d: -f1 | xargs -r -n1 lvremove -ff -y || true")

        # ================================================
        # Eliminar Volume Groups
        # ================================================
        print("[STEP] Removing all Volume Groups on this disk...")
        ejecutar("vgdisplay --colon 2>/dev/null | cut -d: -f1 | xargs -r -n1 vgremove -ff -y || true")

        # ================================================
        # Eliminar Physical Volumes
        # ================================================
        print("[STEP] Removing all Physical Volumes on this disk...")
        ejecutar("pvdisplay --colon 2>/dev/null | cut -d: -f1 | xargs -r -n1 pvremove -ff -y || true")

        # ================================================
        # Detener y limpiar cualquier RAID
        # ================================================
        print("[STEP] Stopping any RAID arrays containing this disk...")
        ejecutar("mdadm --detail --scan | awk '{print $2}' | xargs -r -n1 mdadm --stop || true")
        ejecutar(f"mdadm --zero-superblock {disco} || true")

        # ================================================
        # Limpiar firmas y tabla de particiones
        # ================================================
        print("[STEP] Wiping all signatures and partition table...")
        ejecutar(f"wipefs -a {disco} || true")
        ejecutar(f"sgdisk --zap-all {disco} || true")

        # ================================================
        # Zeroing rápido para cabecera
        # ================================================
        print("[STEP] Zeroing first 10MB for full clean slate...")
        ejecutar(f"dd if=/dev/zero of={disco} bs=1M count=10 conv=fdatasync status=none || true")
        ejecutar(f"blkdiscard {disco} || true")
        ejecutar(f'sudo sgdisk --zap-all {disco}')

        print(f"[OK] Disk {disco} fully cleaned and ready for reuse.\n")

        # ================================================
        # Crear nueva estructura GPT + partición
        # ================================================
        if not ejecutar(f"parted -s {disco} mklabel gpt"):
            print(f"[ERROR] Failed to create GPT on {disco}")
            continue

        ejecutar(f"parted -s {disco} mkpart primary 1MiB {tamaño_input}")

        # Obtener nombre de la nueva partición
        part = disco + "1" if "nvme" not in disco else disco + "p1"
        print(f"[INFO] Formatting {part} as {tipo_fs}...")
        ejecutar(f"mkfs.{tipo_fs} -F {part}")

        print(f"[OK] {disco} fully wiped and formatted ({tipo_fs}, {tamaño_input}).\n")

        print("[INFO] All selected disks cleaned and formatted uniformly.")

def safe_int_input(prompt):
    """Input integer safely, stripping non-numeric characters."""
    while True:
        raw = input(prompt).strip()
        # Filtrar caracteres no numéricos
        raw = ''.join(ch for ch in raw if ch.isdigit())
        if raw.isdigit():
            return int(raw)
        print("[WARN] Invalid input. Please enter a numeric value.")

def convertir_a_kb(valor):
    valor = valor.upper()
    if valor.endswith("K"):
        return int(valor[:-1])
    elif valor.endswith("M"):
        return int(float(valor[:-1]) * 1024)
    elif valor.endswith("G"):
        return int(float(valor[:-1]) * 1024 * 1024)
    else:
        return int(valor)
# ==============================
# System variables
# ==============================
punto_montaje = {
    "mount":""
}



# ==============================
# RAID + Manager + LVM Functions
# ==============================

def crear_raid(tipo, discos, nombre_raid):
    """Create RAID device using mdadm."""
    nivel = str(tipo)
    discos_str = " ".join(discos)
    cmd = f"mdadm --create /dev/{nombre_raid} --level={nivel} --raid-devices={len(discos)} {discos_str}"
    return ejecutar(cmd)

def crear_vg(nombre_vg, dispositivo):
    """Create Volume Group on a given device."""
    return ejecutar(f"vgcreate {nombre_vg} {dispositivo}")

def crear_lv(nombre_lv, tamaño, nombre_vg):
    """Create Logical Volume within a Volume Group."""
    return ejecutar(f"lvcreate -L {tamaño} -n {nombre_lv} {nombre_vg}")

def formatear_lv(nombre_vg, nombre_lv, tipo_fs="ext4"):
    """Format LV with filesystem."""
    return ejecutar(f"mkfs.{tipo_fs} /dev/{nombre_vg}/{nombre_lv}")

def montar_lv(nombre_vg, nombre_lv, punto_montaje):
    """Mount LV to directory."""
    os.makedirs(punto_montaje, exist_ok=True)
    return ejecutar(f"mount /dev/{nombre_vg}/{nombre_lv} {punto_montaje}")


def añadir_disco_repuesto(nombre_raid, disco_repuesto):
    """Add a spare disk to an existing RAID array."""
    print(f"[INFO] Adding spare disk {disco_repuesto} to RAID {nombre_raid}...")
    cmd = f"mdadm --add /dev/{nombre_raid} {disco_repuesto}"
    if ejecutar(cmd):
        print(f"[OK] Spare disk {disco_repuesto} successfully added to {nombre_raid}.")
    else:
        print(f"[ERROR] Failed to add {disco_repuesto} to {nombre_raid}.")


def mostrar_status_raids():
    """Show status of all active RAID arrays in the system."""
    print("[INFO] Scanning active RAID arrays...")

    try:
        # Leer /proc/mdstat para detectar RAIDs activos
        with open("/proc/mdstat", "r") as f:
            contenido = f.read()

        # Buscar los dispositivos RAID (líneas que empiecen con 'md')
        raids = []
        for linea in contenido.splitlines():
            if linea.startswith("md"):
                nombre = linea.split()[0]
                raids.append(nombre)

        if not raids:
            print("[INFO] No RAID arrays detected.")
            return

        # Mostrar estado detallado de cada RAID encontrado
        for raid in raids:
            print(f"\n========== RAID: /dev/{raid} ==========")
            ejecutar(f"mdadm --detail /dev/{raid}")
            print("======================================")

    except FileNotFoundError:
        print("[ERROR] /proc/mdstat not found. Is mdadm installed and RAID active?")
    except Exception as e:
        print(f"[ERROR] Failed to check RAID status: {e}")


def menu_gestion_raid():
    """Advanced RAID + LVM management console."""
    while True:
        print("""
========== RAID / LVM MANAGEMENT ==========
1 Add disk to RAID
2 Remove disk from RAID
3 Extend VG
4 Reduce VG
5 Create LV
6 Extend LV
7 Reduce LV
8 Split LV (snapshot or clone)
9 Delete LV
10 Delete VG
11 add spare disk to RAID
12 print a cat if u are fucked up
13 Back to main menu
===========================================
""")
        try:
            O = int(input("Select an option: "))
        except ValueError:
            print("[WARN] Invalid input.")
            continue

        match O:
            # ---------------------------------------------
            case 1:  # ADD DISK
                nombre_raid = input("Enter RAID name (e.g., md0): ")
                disco = input("Enter device to add (e.g., /dev/sdd): ")
                ejecutar(f"mdadm --add /dev/{nombre_raid} {disco}")

            # ---------------------------------------------
            case 2:  # REMOVE DISK
                nombre_raid = input("Enter RAID name (e.g., md0): ")
                disco = input("Enter device to remove (e.g., /dev/sdc): ")
                ejecutar(f"mdadm --fail /dev/{nombre_raid} {disco}")
                ejecutar(f"mdadm --remove /dev/{nombre_raid} {disco}")

            # ---------------------------------------------
            case 3:  # EXTEND VG
                nombre_vg = input("Enter VG name: ")
                disco = input("Enter new device or RAID to add (e.g., /dev/md1 or /dev/sdd1): ")
                ejecutar(f"vgextend {nombre_vg} {disco}")

            # ---------------------------------------------
            case 4:  # REDUCE VG
                nombre_vg = input("Enter VG name: ")
                disco = input("Enter device to remove (e.g., /dev/sdd1): ")
                ejecutar(f"vgreduce {nombre_vg} {disco}")

            # ---------------------------------------------
            case 5:  # CREATE LV
                nombre_vg = input("Enter VG name: ")
                nombre_lv = input("Enter new LV name: ")
                tamaño = input("Enter size (e.g., 10G): ")
                ejecutar(f"lvcreate -L {tamaño} -n {nombre_lv} {nombre_vg}")

            # ---------------------------------------------
            case 6:  # EXTEND LV
                nombre_vg = input("Enter VG name: ")
                nombre_lv = input("Enter LV name to extend: ")
                tamaño = input("Enter additional size (e.g., +5G): ")
                ejecutar(f"lvextend -L{tamaño} /dev/{nombre_vg}/{nombre_lv}")
                ejecutar(f"resize2fs /dev/{nombre_vg}/{nombre_lv}")

            # ---------------------------------------------
            case 7:  # REDUCE LV
                nombre_vg = input("Enter VG name: ")
                nombre_lv = input("Enter LV name to reduce: ")
                tamaño = input("Enter new smaller size (e.g., 10G): ")
                print("[WARN] Ensure filesystem is reduced first (use resize2fs -M).")
                ejecutar(f"lvreduce -L {tamaño} /dev/{nombre_vg}/{nombre_lv}")

            # ---------------------------------------------
            case 8:  # SPLIT LV (snapshot or clone)
                nombre_vg = input("Enter VG name: ")
                nombre_lv = input("Enter LV name to split: ")
                tipo = input("Snapshot (s) or Clone (c)?: ").lower()

                if tipo == "s":
                    snap_name = input("Enter snapshot name: ")
                    tamaño = input("Enter snapshot size (e.g., 5G): ")
                    ejecutar(f"lvcreate -L {tamaño} -s -n {snap_name} /dev/{nombre_vg}/{nombre_lv}")
                    print(f"[INFO] Snapshot {snap_name} created for {nombre_lv}")
                elif tipo == "c":
                    clone_name = input("Enter clone name: ")
                    ejecutar(f"lvcreate -s -n {clone_name} /dev/{nombre_vg}/{nombre_lv}")
                    ejecutar(f"lvconvert --merge /dev/{nombre_vg}/{clone_name}")
                    print(f"[INFO] Clone {clone_name} created and merged.")
                else:
                    print("[WARN] Invalid selection.")

            # ---------------------------------------------
            case 9:  # DELETE LV
                nombre_vg = input("Enter VG name: ").strip()
                nombre_lv = input("Enter LV name to delete: ").strip()
                ruta_lv = f"/dev/{nombre_vg}/{nombre_lv}"

                print(f"[INFO] Checking if {ruta_lv} is mounted...")
                # Verificar si está montado y desmontar
                try:
                    res = subprocess.run(
                        f"findmnt -n -o TARGET {ruta_lv}",
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    punto_montaje = res.stdout.strip()
                    if punto_montaje:
                        print(f"[INFO] LV is mounted at {punto_montaje}, unmounting...")
                        ejecutar(f"umount -f {punto_montaje}")
                    else:
                        print("[INFO] LV is not mounted.")
                except Exception as e:
                    print(f"[WARN] Unable to check mount status: {e}")

                # Borrar el filesystem (wipefs + dd de cabecera)
                print(f"[STEP] Wiping filesystem signatures from {ruta_lv}...")
                ejecutar(f"wipefs -a {ruta_lv}")
                ejecutar(f"dd if=/dev/zero of={ruta_lv} bs=1M count=10 conv=fdatasync status=none")

                # Eliminar el Logical Volume
                print(f"[STEP] Removing LV {nombre_lv} from VG {nombre_vg}...")
                ejecutar(f"lvremove -f {ruta_lv}")

                print(f"[OK] Logical Volume {nombre_lv} fully removed and cleaned.")

            # ---------------------------------------------
            case 10:  # DELETE VG
                nombre_vg = input("Enter VG name to delete: ")
                ejecutar(f"vgremove -f {nombre_vg}")
            # ---------------------------------------------
            case 11:  # ADD SPARE DISK
                nombre_raid = input("Enter RAID name (e.g., md0): ")
                disco_repuesto = input("Enter spare disk device (e.g., /dev/sdd): ")
                añadir_disco_repuesto(nombre_raid, disco_repuesto)
            # ---------------------------------------------
            case 12:  # PRINT A CAT IF U ARE FUCKED UP
                print(r"""
                  ^__^  
                ( o.o ) 
                 > ^ < 
                """)
            # ---------------------------------------------
            case 13:  # EXIT
                print("[INFO] Returning to main menu...")
                break

            case _:
                print("[WARN] Invalid option.")

# ==============================
# RAID Menu Logic
# ==============================

def menu_raid():
    """Handle RAID + LVM configuration with multi-VG/LV support."""
    Z = int(input("Select RAID type:\n1 RAID 0\n2 RAID 1\n3 RAID 5\n4 RAID 10\n> "))

    nombre_raid = input("Enter RAID name (e.g., md0): ")
    discos = input("Enter devices separated by space (e.g., /dev/sdb /dev/sdc): ").split()

    niveles = {1:0, 2:1, 3:5, 4:10}
    nivel_raid = niveles.get(Z)
    if nivel_raid is None:
        print("[ERROR] Invalid RAID selection")
        return

    if not crear_raid(nivel_raid, discos, nombre_raid):
        print("[ERROR] RAID creation failed.")
        return


    print("[INFO] Saving RAID configuration to /etc/mdadm/mdadm.conf...")
    ejecutar("mkdir -p /etc/mdadm")
    ejecutar(f"mdadm --detail --scan >> /etc/mdadm/mdadm.conf")

    print("[INFO] Updating initramfs for boot persistence...")
    ejecutar("update-initramfs -u")

    cantidad_vg = safe_int_input("How many VGs do you want to create?: ")

    for i in range(cantidad_vg):
        nombre_vg = input(f"Enter name for VG #{i+1}: ")
        if not crear_vg(nombre_vg, f"/dev/{nombre_raid}"):
            print(f"[ERROR] VG {nombre_vg} creation failed.")
            continue

        cantidad_lv = int(input(f"How many LVs for {nombre_vg}?: "))

        for j in range(cantidad_lv):
            nombre_lv = input(f"Enter LV name #{j+1} for {nombre_vg}: ")
            tamaño_lv = input(f"Enter size for {nombre_lv} (e.g., 10G): ")
            punto_montaje = input(f"Enter mount point for {nombre_lv} (e.g., /mnt/{nombre_lv}): ")

            if crear_lv(nombre_lv, tamaño_lv, nombre_vg):
                if formatear_lv(nombre_vg, nombre_lv):
                    montar_lv(nombre_vg, nombre_lv, punto_montaje)
                    print(f"[INFO] LV {nombre_lv} successfully created and mounted.")
                else:
                    print(f"[ERROR] Formatting {nombre_lv} failed.")
            else:
                print(f"[ERROR] LV {nombre_lv} creation failed.")

    print("[INFO] RAID and all LVM structures successfully configured.")

# ==============================
# Quotas Config Menu
# ==============================

def quotas_create():
    config_file = "config_hardware.json"
    punto_montaje = None
    #leer el punto de montaje del JSON
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                data = json.load(f)
                punto_montaje = data.get("mount", "").strip()
                if punto_montaje:
                    print(f"[INFO] Mount point loaded from {config_file}: {punto_montaje}")
        except json.JSONDecodeError:
            print(f"[WARN] Invalid JSON format in {config_file}, ignoring file.")
    else:
        print("[INFO] No config_hardware.json found. Manual selection required.")

    #Si json vacio, pedirlo manualmente
    if not punto_montaje or not os.path.exists(punto_montaje):
        quotas_installed = input("[INFO] Does this machine have quotas installed? (Y/N): ").strip().lower()

        if quotas_installed != 'y':
            print("[INFO] Installing quota package...")
            ejecutar("apt-get update && apt-get install -y quota")

        print("\n[INFO] Analyzing /etc/fstab for available mount points...\n")
        with open("/etc/fstab", "r") as f:
            lines = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]

        valid_mounts = []
        for idx, line in enumerate(lines):
            parts = line.split()
            if len(parts) >= 2:
                device, mount = parts[0], parts[1]
                valid_mounts.append((idx, device, mount))
                print(f"[{idx}] DEVICE: {device} | MOUNT: {mount}")

        if not valid_mounts:
            print("[WARN] No valid entries found in /etc/fstab.")
        else:
            print("\n[INFO] Select one of the listed mount points, or type 'new' to create a new one.")
        
        choice = input("Mount point index or 'new': ").strip()

        if choice.lower() == "new":
            ejecutar("clear")
            ejecutar("lsblk -e7")
            nuevo_punto = input("Enter new mount point (e.g., /mnt/data): ").strip()
            device = input("Enter device (e.g., /dev/sdb1): ").strip()
            
            os.makedirs(nuevo_punto, exist_ok=True)
            with open("/etc/fstab", "a") as f:
                f.write(f"{device}\t{nuevo_punto}\text4\tdefaults\t0\t2\n")
            ejecutar(f"mount -a")
            punto_montaje = nuevo_punto
        else:
            try:
                idx = int(choice)
                punto_montaje = valid_mounts[idx][2]
            except (ValueError, IndexError):
                print("[ERROR] Invalid selection.")
                return

        # Guardar punto de montaje en config_hardware.json
        with open(config_file, "w") as f:
            json.dump({"mount": punto_montaje}, f, indent=4)
            print(f"[OK] Saved mount point to {config_file}")

    
    #Validar y habilitar cuotas
    if not os.path.ismount(punto_montaje):
        print(f"[ERROR] {punto_montaje} is not a valid mount point.")
        return

    print("\n[INFO] Enabling quotas in /etc/fstab...")
    try:
        with open("/etc/fstab", "r") as f:
            lineas = f.readlines()

        with open("/etc/fstab", "w") as f:
            for linea in lineas:
                if punto_montaje in linea and "usrquota" not in linea and "grpquota" not in linea:
                    campos = linea.split()
                    if len(campos) >= 4:
                        opciones = campos[3]
                        if "defaults" in opciones:
                            opciones = opciones.replace("defaults", "defaults,usrquota,grpquota")
                        else:
                            opciones += ",usrquota,grpquota"
                        campos[3] = opciones
                        linea = "\t".join(campos) + "\n"
                f.write(linea)

        print("[INFO] Remounting filesystem with quota options...")
        ejecutar(f"mount -o remount {punto_montaje}")

        print("[INFO] Creating quota files...")
        ejecutar(f"quotacheck -cgu {punto_montaje}")
        ejecutar(f"quotaon {punto_montaje}")

        print(f"[OK] Disk quotas successfully enabled on {punto_montaje}.")

    except Exception as e:
        print(f"[ERROR] Failed to configure quotas: {e}")

# ==============================
# quotas config
# ==============================

def quotas_config():
    user_or_group = input("""
    ============== QUOTAS CONFIG MENU ================
    1 Configure user quota
    2 Configure group quota
    3 Set grace period
    20 Back to main menu
    ================================================
    """).strip()

    match user_or_group:
        case "1":
            user = input("Enter username to configure quota: ").strip()
            soft_limit = convertir_a_kb(input("Enter soft limit (e.g., 500M): ").strip())
            hard_limit = convertir_a_kb(input("Enter hard limit (e.g., 1G): ").strip())
            mount_point = input("Enter mount point (default /): ").strip() or "/"
            ejecutar(f"setquota -u {user} {soft_limit} {hard_limit} 0 0 {mount_point}")
            print(f"[OK] User quota applied for {user} on {mount_point}")
        
        case "2":
            group = input("Enter group name to configure quota: ").strip()
            soft_limit = convertir_a_kb(input("Enter soft limit (e.g., 500M): ").strip())
            hard_limit = convertir_a_kb(input("Enter hard limit (e.g., 1G): ").strip())
            mount_point = input("Enter mount point (default /): ").strip() or "/"
            ejecutar(f"setquota -g {group} {soft_limit} {hard_limit} 0 0 {mount_point}")
            print(f"[OK] Group quota applied for {group} on {mount_point}")

        case "3":
            grace_days = input("Enter grace period in days (e.g., 7): ").strip()
            seconds = int(grace_days) * 86400
            mount_point = input("Enter mount point (default /): ").strip() or "/"
            ejecutar(f"setquota -t {seconds} {seconds} {mount_point}")
            print(f"[OK] Grace period set to {grace_days} days for {mount_point}")

        case "20":
            print("[INFO] Returning to main menu.")

        case _:
            print("[WARN] Invalid option.")

def quotas_add():
    try:
        x = int(input("""
        ============== QUOTAS MENU ================
        1 Add user quota
        2 Add group quota 
        3 Delete user quota 
        4 Delete group quota 
        5 Show user quotas
        6 Show group quotas
        7 Back to main menu
        ===========================================
        """).strip())
    except ValueError:
        print("[WARN] Invalid numeric input.")
        return

    match x:
        case 1:
            user = input("Enter username to set quota: ").strip()
            print("[INFO] Opening quota editor (requires root privileges)...")
            ejecutar(f"edquota -u {user}")

        case 2:
            group = input("Enter group name to set quota: ").strip()
            print("[INFO] Opening group quota editor (requires root privileges)...")
            ejecutar(f"edquota -g {group}")

        case 3:
            user = input("Enter username to delete quota: ").strip()
            mount_point = input("Enter mount point (default /): ").strip() or "/"
            print(f"[INFO] Resetting quota for user {user} on {mount_point}...")
            ejecutar(f"setquota -u {user} 0 0 0 0 {mount_point}")
            print(f"[OK] User quota reset for {user}.")

        case 4:
            group = input("Enter group name to delete quota: ").strip()
            mount_point = input("Enter mount point (default /): ").strip() or "/"
            print(f"[INFO] Resetting quota for group {group} on {mount_point}...")
            ejecutar(f"setquota -g {group} 0 0 0 0 {mount_point}")
            print(f"[OK] Group quota reset for {group}.")

        case 5:
            mount_point = input("Enter mount point to display (default /): ").strip() or "/"
            ejecutar(f"repquota -u {mount_point}")

        case 6:
            mount_point = input("Enter mount point to display (default /): ").strip() or "/"
            ejecutar(f"repquota -g {mount_point}")

        case 7:
            print("[INFO] Returning to main menu.")

        case _:
            print("[WARN] Invalid option.")

# ==============================
# Main Menu
# ==============================

def main():
    while True:
        try:
            O = int(input(
                "\nSelect an option:\n"
                "1 RAID Configuration\n"
                "2 quotas config\n"
                "3 Exit\n> "
            ))

            match O:
                case 1:
                    AMOGAS = int(input(
                        "\nSelect an option:\n"
                        "1 set up a raid\n"
                        "2 Manage raid\n"
                        "3 check status\n"
                        "4 format disks\n"
                        "5 Exit\n>"
                        ))
                    match AMOGAS:
                        case 1:
                            ejecutar("clear")
                            menu_raid()
                        case 2:
                            ejecutar("clear")
                            menu_gestion_raid()
                        case 3:
                            ejecutar("clear")
                            mostrar_status_raids()
                        case 4:
                            ejecutar("clear")
                            formatear_discos()
                        case 5:
                            print("[INFO] Exiting.")   
                            break    
                        case _:
                            print("[WARN] invalido")
                case 2:
                    Z = int(input(
                        "\nSelect an option:\n"
                        "1 set up quotas\n"
                        "2 add users/groups\n"
                        "3 config quota\n"
                        "4 exit\n> "
                    ))
                    match Z:
                        case 1:
                            ejecutar("clear")
                            quotas_create()
                            with open("config_hardware.json", "w") as f:
                                json.dump(punto_montaje, f, indent=4)
                        case 2:
                            ejecutar("clear")
                            quotas_config()

                        case 3:
                            quotas_add()
                        case 4:
                            print("[INFO] Exiting.")
                            break
                        case _:
                            print("[WARN] Invalid option.")
                case 3:
                    print("[INFO] Exiting.")
                    break
                case _:
                    print("[WARN] Invalid option.")
        except KeyboardInterrupt:
            print("\n[INFO] Interrupted by user.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")

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