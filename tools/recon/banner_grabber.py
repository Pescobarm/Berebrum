"""
Berebrum - Service Banner Grabber
Identificación de servicios y versiones mediante banner grabbing
"""

import socket
import ssl
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class BannerGrabber:
    """
    Extrae banners de servicios para identificar versiones y tecnologías
    """

    # Probes HTTP para diferentes servicios
    SERVICE_PROBES = {
        "http": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "ftp": b"",  # FTP envía banner automáticamente
        "smtp": b"EHLO test\r\n",
        "ssh": b"",  # SSH envía banner automáticamente
        "telnet": b"",
        "pop3": b"",
        "imap": b"",
        "mysql": b"",
        "postgresql": b"",
        "rdp": b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        "smb": b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8",
    }

    # Patrones para detectar versiones
    VERSION_PATTERNS = {
        "apache": r"Apache/([0-9.]+)",
        "nginx": r"nginx/([0-9.]+)",
        "iis": r"Microsoft-IIS/([0-9.]+)",
        "php": r"PHP/([0-9.]+)",
        "openssh": r"OpenSSH[_-]([0-9.]+[a-z0-9]*)",
        "mysql": r"MySQL ([0-9.]+)",
        "postgresql": r"PostgreSQL ([0-9.]+)",
        "vsftpd": r"vsftpd ([0-9.]+)",
        "proftpd": r"ProFTPD ([0-9.]+)",
        "sendmail": r"Sendmail ([0-9.]+)",
        "postfix": r"Postfix",
        "dovecot": r"Dovecot ([0-9.]+)",
    }

    # CVEs conocidos por versión
    KNOWN_VULNERABILITIES = {
        "OpenSSH_7.4": ["CVE-2018-15473: Username enumeration"],
        "Apache/2.4.29": ["CVE-2019-0211: Privilege escalation"],
        "nginx/1.10": ["CVE-2017-7529: Integer overflow"],
        "vsftpd 2.3.4": ["CVE-2011-2523: Backdoor command execution"],
        "ProFTPD 1.3.3c": ["CVE-2010-4221: Telnet IAC stack overflow"],
    }

    def __init__(self, timeout: float = 2.0):
        """
        Inicializar banner grabber

        Args:
            timeout: Timeout por conexión
        """
        self.timeout = timeout

    def grab_banner(
        self,
        target: str,
        port: int,
        service: Optional[str] = None,
        use_ssl: bool = False,
    ) -> Dict[str, any]:
        """
        Obtener banner de un servicio

        Args:
            target: IP o hostname
            port: Puerto del servicio
            service: Tipo de servicio (opcional)
            use_ssl: Usar SSL/TLS

        Returns:
            Información del banner
        """
        try:
            # Crear socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Conectar
            sock.connect((target, port))

            # Envolver en SSL si es necesario
            if use_ssl or port in [443, 8443, 465, 993, 995]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            # Enviar probe si se conoce el servicio
            if service and service in self.SERVICE_PROBES:
                probe = self.SERVICE_PROBES[service]
                if b"{host}" in probe:
                    probe = probe.replace(b"{host}", target.encode())
                if probe:
                    sock.send(probe)

            # Recibir banner
            banner = sock.recv(4096).decode("utf-8", errors="ignore").strip()
            sock.close()

            # Analizar banner
            analysis = self._analyze_banner(banner, port)

            return {
                "target": target,
                "port": port,
                "service": service or "Unknown",
                "banner": banner,
                "server": analysis["server"],
                "version": analysis["version"],
                "technologies": analysis["technologies"],
                "vulnerabilities": analysis["vulnerabilities"],
                "risk_level": analysis["risk_level"],
                "timestamp": datetime.now().isoformat(),
            }

        except socket.timeout:
            return self._error_result(target, port, "Timeout")
        except ConnectionRefusedError:
            return self._error_result(target, port, "Connection refused")
        except Exception as e:
            return self._error_result(target, port, str(e))

    def _analyze_banner(self, banner: str, port: int) -> Dict[str, any]:
        """
        Analizar banner para extraer información

        Args:
            banner: Banner del servicio
            port: Puerto

        Returns:
            Análisis del banner
        """
        server = "Unknown"
        version = "Unknown"
        technologies = []
        vulnerabilities = []
        risk_level = "Low"

        # Detectar servidor y versión
        for tech, pattern in self.VERSION_PATTERNS.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if tech in ["apache", "nginx", "iis"]:
                    server = tech.capitalize()
                    version = match.group(1) if match.groups() else "Unknown"
                technologies.append(
                    f"{tech.upper()}: {match.group(1) if match.groups() else 'detected'}"
                )

        # Detectar otras tecnologías
        if "PHP" in banner:
            technologies.append("PHP")
        if "Python" in banner:
            technologies.append("Python")
        if "Express" in banner:
            technologies.append("Express.js")
        if "ASP.NET" in banner:
            technologies.append("ASP.NET")

        # Buscar vulnerabilidades conocidas
        for vuln_sig, vulns in self.KNOWN_VULNERABILITIES.items():
            if vuln_sig.lower() in banner.lower():
                vulnerabilities.extend(vulns)
                risk_level = "Critical"

        # Evaluar riesgo por información expuesta
        if version != "Unknown" and version:
            risk_level = "Medium" if risk_level == "Low" else risk_level

        # Detectar banners que revelan demasiada información
        if any(
            keyword in banner.lower()
            for keyword in ["ubuntu", "debian", "centos", "windows"]
        ):
            risk_level = "Medium" if risk_level == "Low" else risk_level

        return {
            "server": server,
            "version": version,
            "technologies": technologies,
            "vulnerabilities": vulnerabilities,
            "risk_level": risk_level,
        }

    def _error_result(self, target: str, port: int, error: str) -> Dict[str, any]:
        """
        Resultado de error
        """
        return {
            "target": target,
            "port": port,
            "service": "Unknown",
            "banner": None,
            "server": "Unknown",
            "version": "Unknown",
            "technologies": [],
            "vulnerabilities": [],
            "risk_level": "Unknown",
            "error": error,
            "timestamp": datetime.now().isoformat(),
        }

    def scan_multiple_ports(self, target: str, ports: List[int]) -> Dict[str, any]:
        """
        Obtener banners de múltiples puertos

        Args:
            target: IP o hostname
            ports: Lista de puertos

        Returns:
            Resultados de todos los puertos
        """
        results = []

        for port in ports:
            # Determinar si usar SSL
            use_ssl = port in [443, 8443, 465, 993, 995]

            # Determinar servicio por puerto
            service_map = {
                21: "ftp",
                22: "ssh",
                23: "telnet",
                25: "smtp",
                80: "http",
                110: "pop3",
                143: "imap",
                443: "http",
                3306: "mysql",
                5432: "postgresql",
                8080: "http",
            }
            service = service_map.get(port)

            result = self.grab_banner(target, port, service, use_ssl)
            if result["banner"]:  # Solo añadir si se obtuvo banner
                results.append(result)

        # Generar resumen
        critical_count = sum(1 for r in results if r["risk_level"] == "Critical")
        high_count = sum(1 for r in results if r["risk_level"] == "High")
        medium_count = sum(1 for r in results if r["risk_level"] == "Medium")

        all_vulns = []
        for r in results:
            all_vulns.extend(r["vulnerabilities"])

        return {
            "target": target,
            "total_ports": len(ports),
            "successful_grabs": len(results),
            "results": results,
            "summary": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "total_vulnerabilities": len(all_vulns),
            },
            "recommendations": self._generate_recommendations(results),
            "timestamp": datetime.now().isoformat(),
        }

    def _generate_recommendations(self, results: List[Dict]) -> List[str]:
        """
        Generar recomendaciones de seguridad
        """
        recommendations = []

        for result in results:
            if result["version"] != "Unknown":
                recommendations.append(
                    f"Puerto {result['port']}: Banner revela versión ({result['server']} {result['version']}). "
                    "Considerar ocultar información de versión en configuración del servidor."
                )

            if result["vulnerabilities"]:
                recommendations.append(
                    f"Puerto {result['port']}: Vulnerabilidades conocidas detectadas. "
                    "Actualizar a la última versión estable inmediatamente."
                )

            if result["risk_level"] == "Critical":
                recommendations.append(
                    f"Puerto {result['port']}: CRÍTICO - Requiere atención inmediata. "
                    "Revisar y aplicar parches de seguridad."
                )

        if not recommendations:
            recommendations.append(
                "No se detectaron problemas críticos en los banners analizados."
            )

        return recommendations


def grab_service_banner(target: str, port: int) -> Dict[str, any]:
    """
    Función de utilidad para obtener banner de un servicio
    """
    grabber = BannerGrabber()
    return grabber.grab_banner(target, port)


def grab_banners(target: str, ports: List[int] = None) -> Dict[str, any]:
    """
    Función de utilidad para obtener banners de múltiples puertos

    Args:
        target: IP o hostname objetivo
        ports: Lista de puertos a escanear (default: puertos comunes)

    Returns:
        Diccionario con resultados del escaneo
    """
    if ports is None:
        # Puertos por defecto
        ports = [21, 22, 23, 80, 443, 3306, 3389]

    grabber = BannerGrabber()
    return grabber.scan_multiple_ports(target, ports)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Uso: python banner_grabber.py <target> <port1,port2,port3>")
        sys.exit(1)

    target = sys.argv[1]
    ports = [int(p) for p in sys.argv[2].split(",")]

    grabber = BannerGrabber()
    result = grabber.scan_multiple_ports(target, ports)

    print(f"\n=== Banner Grabbing Results ===")
    print(f"Target: {result['target']}")
    print(f"Successful grabs: {result['successful_grabs']}/{result['total_ports']}")

    for r in result["results"]:
        print(f"\n--- Puerto {r['port']} ({r['service']}) ---")
        print(f"Server: {r['server']} {r['version']}")
        print(f"Risk: {r['risk_level']}")
        if r["technologies"]:
            print(f"Technologies: {', '.join(r['technologies'])}")
        if r["vulnerabilities"]:
            print(f"Vulnerabilities:")
            for vuln in r["vulnerabilities"]:
                print(f"  • {vuln}")
        if r["banner"]:
            print(f"Banner: {r['banner'][:200]}")
