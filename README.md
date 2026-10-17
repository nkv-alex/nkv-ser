# NKV SER — Linux Network Services Automation

Herramienta de administración de sistemas Linux desarrollada en Python para automatizar la configuración de interfaces de red, servicios de infraestructura y comunicaciones entre equipos.

El proyecto está orientado a entornos **Debian 13**, con funcionalidades para configurar servicios de red, gestionar copias de seguridad de archivos de configuración y realizar tareas de administración desde una terminal.

## Características principales

### Configuración de red

- Detección de interfaces de red IPv4.
- Clasificación de interfaces internas y externas.
- Configuración de interfaces mediante Netplan.
- Asignación de direcciones mediante DHCP o configuración estática.
- Configuración de NAT y reglas de encaminamiento.
- Activación del reenvío de paquetes IP.
- Copias de seguridad de configuraciones de red.
- Restauración de versiones anteriores de archivos respaldados.

### Automatización de servicios

El módulo principal permite configurar servicios habituales de infraestructura:

| Servicio | Funcionalidad |
|---|---|
| SSH | Configuración del acceso remoto |
| DHCP | Configuración del direccionamiento automático |
| NAT | Compartición y encaminamiento de conexiones |
| DNS | Resolución de nombres mediante dnsmasq |
| FTP | Configuración del servidor vsftpd |
| HTTPS | Configuración de Apache2 y certificados SSL |
| Mail | Configuración del servidor Postfix |
| Samba | Compartición de archivos con clientes de red |
| NFS | Compartición de directorios entre sistemas Linux |

Las opciones disponibles dependen del módulo y de los paquetes instalados.

### Descubrimiento y comunicación UDP

`listener.py` implementa un servicio de escucha UDP que:

- Escucha en el puerto `50000`.
- Responde a mensajes de descubrimiento `DISCOVER_REQUEST`.
- Identifica el equipo mediante su hostname y dirección MAC.
- Procesa comandos internos como `test` y `config_dhcp`.
- Permite ejecutar acciones de administración de red desde el listener.

**Advertencia:** este mecanismo no implementa por sí mismo una autenticación robusta de los emisores. No debe exponerse a redes no confiables.

### Desinstalación y limpieza

`purge.py` proporciona un menú para desinstalar servicios y eliminar sus configuraciones asociadas.

Incluye opciones para SSH, DHCP, NAT, DNS, FTP, HTTPS, correo, Samba y NFS, además de una opción de purga completa.

La purga completa puede eliminar configuraciones y datos de servicios. Debe utilizarse con precaución.

## Estructura del proyecto

```text
nkv-ser/
├── conf-serv.py    # Configuración de red y servicios
├── listener.py     # Escucha y comunicación UDP
├── purge.py        # Desinstalación y limpieza
├── manual.txt      # Manual de uso del proyecto
├── debian/         # Archivos de empaquetado Debian
└── README.md       # Documentación del proyecto
```

## Requisitos

- Debian 13 o un entorno Debian compatible.
- Python 3.
- Permisos de administrador para modificar la configuración del sistema.
- Interfaces de red funcionales.
- Netplan para las funciones que modifican sus archivos.
- Paquetes y servicios necesarios para cada funcionalidad.
- PyYAML para gestionar archivos YAML desde Python.

Entre las herramientas del sistema utilizadas se encuentran `ip`, `iptables`, `systemctl`, `netplan`, `openssl` y diferentes utilidades de administración de servicios.

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/nkv-alex/nkv-ser.git
cd nkv-ser
```

### 2. Instalar dependencias básicas

```bash
sudo apt update
sudo apt install python3 python3-yaml git
```

Instala también las dependencias específicas de cada servicio según las funciones que vayas a utilizar.

### 3. Revisar el código antes de ejecutarlo

```bash
python3 -m py_compile conf-serv.py
python3 -m py_compile listener.py
python3 -m py_compile purge.py
```

Esta comprobación detecta errores de sintaxis, pero no garantiza que las operaciones de red funcionen correctamente.

### 4. Ejecutar los módulos

Configuración de servicios:

```bash
sudo python3 conf-serv.py
```

Listener UDP:

```bash
sudo python3 listener.py
```

Desinstalación de servicios:

```bash
sudo python3 purge.py
```

Ejecuta únicamente los módulos que necesites y revisa sus opciones antes de confirmar operaciones.

## Configuración y archivos de datos

El proyecto utiliza diferentes rutas de configuración:

- `interfaces.json`: guarda las interfaces detectadas y su clasificación.
- `/etc/netplan/`: contiene las configuraciones de red administradas por Netplan.
- `/etc/netplan/backups_nat_helper/`: almacena copias de seguridad de configuraciones modificadas.
- `res.log`: archivo de registro previsto para determinadas operaciones.

Algunos archivos se generan o modifican durante la ejecución. La ubicación de `interfaces.json` y `res.log` depende del directorio de trabajo actual.

## Seguridad

Esta herramienta modifica directamente servicios y configuraciones del sistema operativo. Antes de utilizarla en un servidor real:

- Realiza una copia de seguridad de los archivos de configuración.
- Prueba los cambios en una máquina virtual o un entorno aislado.
- Verifica las reglas de firewall y las interfaces seleccionadas.
- No expongas el listener UDP a redes públicas.
- No permitas comandos remotos sin autenticación y autorización.
- Comprueba los permisos de los directorios compartidos.
- Revisa las operaciones de borrado antes de ejecutar `purge.py`.
- Evita ejecutar el programa por SSH si un cambio de red puede interrumpir tu conexión administrativa.

La opción de purga completa es especialmente destructiva: puede eliminar archivos de configuración, reglas de firewall, certificados y datos de servicios.

## Estado del proyecto

Proyecto de automatización de servicios Linux en desarrollo. La compatibilidad y disponibilidad de cada funcionalidad deben verificarse en el entorno de destino antes de su uso.

## Autor

**nkv-alex**

Repositorio: https://github.com/nkv-alex/nkv-ser

