# core/attack_mapping.py

"""
CEREBRO DE ATAQUE BEREBRUM
Mapeo de vulnerabilidades conocidas a módulos de Metasploit.
Formato:
    "Firma del servicio": {
        "module": "ruta/al/exploit",
        "default_port": puerto_estandar,
        "payload": "payload/sugerido (opcional)"
    }
"""

ATTACK_MAP = {
    # 1. El clásico Backdoor de vsFTPd (Metasploitable 2)
    "vsftpd 2.3.4": {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "default_port": 21,
        "description": "Backdoor smile face en vsFTPd 2.3.4",
    },
    # 2. EternalBlue (Windows 7/2008 - El rey de los exploits)
    "Windows 7": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "default_port": 445,
        "description": "SMB Remote Code Execution (EternalBlue)",
    },
    "Windows Server 2008": {
        "module": "exploit/windows/smb/ms17_010_eternalblue",
        "default_port": 445,
        "description": "SMB Remote Code Execution (EternalBlue)",
    },
    # 3. DistCC (Compilador distribuido inseguro)
    "distcc": {
        "module": "exploit/unix/misc/distcc_exec",
        "default_port": 3632,
        "description": "DistCC Daemon Command Execution",
    },
    # 4. UnrealIRCd Backdoor
    "UnrealIRCd": {
        "module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "default_port": 6667,
        "description": "UnrealIRCd 3.2.8.1 Backdoor Command Execution",
    },
    # 5. Java RMI Server
    "Java RMI": {
        "module": "exploit/multi/misc/java_rmi_server",
        "default_port": 1099,
        "description": "Java RMI Server Insecure Default Configuration",
    },
}


def get_exploit_for_service(banner):
    """
    Busca en el mapa si el banner detectado tiene un exploit asociado.
    Retorna la configuración del ataque o None.
    """
    banner_lower = banner.lower()

    for signature, config in ATTACK_MAP.items():
        if signature.lower() in banner_lower:
            return config

    return None
