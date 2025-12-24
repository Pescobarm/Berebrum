"""
CORE: MSF MAPPING
Mapea servicios detectados (Nmap) a módulos de explotación de Metasploit.
"""

ATTACK_KNOWLEDGE_BASE = {
    "vsftpd": [
        {
            "version_keyword": "2.3.4",
            "module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "mitre_id": "T1190",
            "cvss_score": 9.8,
            "severity": "Critical",
            "payload_compatible": ["cmd/unix/interact"],
        }
    ],
    "proftpd": [
        {
            "version_keyword": "1.3.3",
            "module": "exploit/unix/ftp/proftpd_133c_backdoor",
            "mitre_id": "T1190",
            "cvss_score": 10.0,
            "severity": "Critical",
            "payload_compatible": ["cmd/unix/reverse"],
        }
    ],
    "microsoft-ds": [
        {
            "version_keyword": "Windows 7",
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "mitre_id": "T1210",
            "cvss_score": 9.3,
            "severity": "Critical",
            "payload_compatible": ["windows/x64/meterpreter/reverse_tcp"],
        },
        {
            "version_keyword": "Samba",
            "module": "exploit/multi/samba/usermap_script",
            "mitre_id": "T1190",
            "cvss_score": 9.8,
            "severity": "Critical",
            "payload_compatible": ["cmd/unix/reverse_netcat"],
        },
    ],
    "http": [
        {
            "version_keyword": "Apache Struts",
            "module": "exploit/multi/http/struts2_content_type_ognl",
            "mitre_id": "T1190",
            "cvss_score": 9.8,
            "severity": "Critical",
            "payload_compatible": ["java/meterpreter/reverse_tcp"],
        }
    ],
}


def get_exploit_config(service_name, banner_or_version):
    """
    Retorna la configuración del exploit si encuentra coincidencia.
    """
    if not service_name:
        return None
    s_key = service_name.lower()

    # Busca la clave del servicio
    matched_key = next((k for k in ATTACK_KNOWLEDGE_BASE if k in s_key), None)

    if matched_key:
        candidates = ATTACK_KNOWLEDGE_BASE[matched_key]
        # Si no hay versión específica, devolvemos el primero como 'mejor intento'
        # O iteramos buscando coincidencia
        for exploit in candidates:
            if (
                str(exploit["version_keyword"]).lower()
                in str(banner_or_version).lower()
            ):
                return exploit
        # Fallback: Retorna el primero si es el servicio correcto pero versión desconocida
        # return candidates[0]

    return None
