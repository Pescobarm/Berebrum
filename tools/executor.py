"""
Berebrum - Tool Executor
Ejecuta herramientas con validación de scope y logging automático
VERSIÓN AUTOCONTENIDA - No requiere módulos externos
"""

from core.database import db_manager
from datetime import datetime
import time
import ipaddress


class SimpleCVSS:
    """Calculador CVSS simplificado"""

    @staticmethod
    def quick_score(
        network_accessible=True, requires_auth=False, user_interaction=False
    ):
        """
        Calcular CVSS score rápido basado en características

        Returns:
            (score, severity, vector)
        """
        # Base score según accesibilidad
        if network_accessible and not requires_auth and not user_interaction:
            score = 9.8
            severity = "Critical"
        elif network_accessible and not requires_auth:
            score = 8.1
            severity = "High"
        elif network_accessible:
            score = 6.5
            severity = "Medium"
        else:
            score = 4.3
            severity = "Low"

        # Vector simplificado
        av = "N" if network_accessible else "L"
        ac = "L"
        pr = "N" if not requires_auth else "L"
        ui = "N" if not user_interaction else "R"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:U/C:H/I:H/A:H"

        return score, severity, vector


class SimpleScope:
    """Validador de scope simplificado"""

    def __init__(self, scope_ips: str):
        """
        Args:
            scope_ips: IPs/Redes separadas por coma (192.168.1.0/24,10.0.0.0/8)
        """
        self.networks = []

        for scope in scope_ips.split(","):
            scope = scope.strip()
            try:
                # Intentar como red
                if "/" in scope:
                    self.networks.append(ipaddress.ip_network(scope, strict=False))
                else:
                    # IP individual
                    self.networks.append(
                        ipaddress.ip_network(f"{scope}/32", strict=False)
                    )
            except:
                pass

    def is_in_scope(self, target: str) -> tuple:
        """
        Verificar si target está en scope

        Returns:
            (bool, str): (is_valid, reason)
        """
        # Si no hay networks, permitir todo (desarrollo)
        if not self.networks:
            return True, "No scope defined"

        try:
            # Extraer IP del target (puede ser URL)
            if target.startswith("http://") or target.startswith("https://"):
                # Es URL, extraer hostname
                from urllib.parse import urlparse

                parsed = urlparse(target)
                hostname = parsed.hostname
                if not hostname:
                    return False, "Invalid URL"
                target = hostname

            # Intentar resolver como IP
            try:
                ip = ipaddress.ip_address(target)
            except:
                # Puede ser hostname, intentar resolver
                import socket

                try:
                    target = socket.gethostbyname(target)
                    ip = ipaddress.ip_address(target)
                except:
                    return False, f"Cannot resolve: {target}"

            # Verificar si está en alguna red del scope
            for network in self.networks:
                if ip in network:
                    return True, f"In scope: {network}"

            return False, f"IP {ip} not in scope"

        except Exception as e:
            return False, f"Validation error: {str(e)}"


class ToolExecutor:
    """
    Ejecutor de herramientas con integración completa
    """

    def __init__(self, project_id: int):
        """
        Inicializar ejecutor

        Args:
            project_id: ID del proyecto activo
        """
        self.project_id = project_id
        self.project = db_manager.get_project(project_id)
        self.scope_validator = SimpleScope(self.project.scope_ips)

    def execute(self, tool_name: str, tool_function, target: str, **kwargs):
        """
        Ejecutar herramienta con validación y logging

        Args:
            tool_name: Nombre de la herramienta
            tool_function: Función a ejecutar
            target: Target del escaneo
            **kwargs: Parámetros adicionales

        Returns:
            Resultado de la ejecución
        """
        start_time = time.time()

        # Validar scope
        try:
            is_valid, reason = self.scope_validator.is_in_scope(target)
            if not is_valid:
                # Log blocked attempt
# [FIX]                 db_manager.create_log(
# [FIX]                     project_id=self.project_id,
# [FIX]                     tool_name=tool_name,
# [FIX]                     tool_category="BLOCKED",
# [FIX]                     target=target,
# [FIX]                     command=f"{tool_name} {target}",
# [FIX]                     output=None,
# [FIX]                     success=False,
# [FIX]                     error_message=f"BLOCKED: {reason}",
# [FIX]                     duration_seconds=0,
# [FIX]                 )

                return {
                    "success": False,
                    "error": f"Target fuera de scope: {reason}",
                    "blocked": True,
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error validando scope: {str(e)}",
                "blocked": True,
            }

        # Ejecutar herramienta
        try:
            result_data = tool_function(target, **kwargs)

            duration = time.time() - start_time

            # Determinar MITRE technique basado en la herramienta
            mitre_map = {
                "Port Scanner": (
                    "T1046",
                    "Network Service Discovery",
                    "Reconnaissance",
                ),
                "Banner Grabber": (
                    "T1046",
                    "Network Service Scanning",
                    "Reconnaissance",
                ),
                "Subdomain Enumerator": ("T1595", "Active Scanning", "Reconnaissance"),
                "Web Directory Scanner": (
                    "T1083",
                    "File and Directory Discovery",
                    "Discovery",
                ),
                "HTTP Header Analyzer": (
                    "T1592",
                    "Gather Victim Host Information",
                    "Reconnaissance",
                ),
                "DNS Information Gatherer": (
                    "T1590",
                    "Gather Victim Network Information",
                    "Reconnaissance",
                ),
                "SSL/TLS Analyzer": ("T1040", "Network Sniffing", "Collection"),
                "Vulnerability Scanner": (
                    "T1190",
                    "Exploit Public-Facing Application",
                    "Initial Access",
                ),
                "SQL Injection Scanner": (
                    "T1190",
                    "Exploit Public-Facing Application",
                    "Initial Access",
                ),  # ← AGREGAR ESTA LÍNEA
            }

            mitre_tech_id, mitre_tech_name, mitre_tactic = mitre_map.get(
                tool_name, ("", "", "")
            )

            # =====================================================
            # FIX: Serializar resultado completo sin límite
            # =====================================================
            import json

            try:
                output_str = json.dumps(result_data, indent=2, default=str)
            except Exception as e:
                # Fallback si falla JSON
                output_str = str(result_data)

            # Guardar log
# [FIX]             db_manager.create_log(
# [FIX]                 project_id=self.project_id,
# [FIX]                 tool_name=tool_name,
# [FIX]                 tool_category=self._get_category(tool_name),
# [FIX]                 target=target,
# [FIX]                 command=f"{tool_name} {target} {kwargs}",
# [FIX]                 output=output_str,  # ← SIN LÍMITE [:5000]
# [FIX]                 success=True,
# [FIX]                 mitre_technique_id=mitre_tech_id,
# [FIX]                 mitre_technique_name=mitre_tech_name,
# [FIX]                 mitre_tactic=mitre_tactic,
# [FIX]                 duration_seconds=duration,
# [FIX]             )

            # Procesar vulnerabilidades si las hay
            if "vulnerabilities" in result_data:
                self._process_vulnerabilities(
                    result_data["vulnerabilities"],
                    tool_name,
                    target,
                    mitre_tech_id,
                    mitre_tech_name,
                    mitre_tactic,
                )

            # Añadir metadata
            result_data["execution_metadata"] = {
                "duration": duration,
                "timestamp": datetime.now().isoformat(),
                "tool": tool_name,
                "success": True,
            }

            return result_data

        except Exception as e:
            duration = time.time() - start_time

            # Guardar log de error
# [FIX]             db_manager.create_log(
# [FIX]                 project_id=self.project_id,
# [FIX]                 tool_name=tool_name,
# [FIX]                 tool_category=self._get_category(tool_name),
# [FIX]                 target=target,
# [FIX]                 command=f"{tool_name} {target} {kwargs}",
# [FIX]                 output=None,
# [FIX]                 success=False,
# [FIX]                 error_message=str(e),
# [FIX]                 duration_seconds=duration,
# [FIX]             )

            return {
                "success": False,
                "error": str(e),
                "execution_metadata": {
                    "duration": duration,
                    "timestamp": datetime.now().isoformat(),
                    "tool": tool_name,
                    "success": False,
                },
            }

    def _get_category(self, tool_name: str) -> str:
        """Obtener categoría de la herramienta"""
        category_map = {
            "Port Scanner": "RECON",
            "Banner Grabber": "RECON",
            "Subdomain Enumerator": "RECON",
            "Web Directory Scanner": "RECON",
            "HTTP Header Analyzer": "RECON",
            "DNS Information Gatherer": "RECON",
            "SSL/TLS Analyzer": "RECON",
            "Vulnerability Scanner": "EXPLOIT",
            "SQL Injection Scanner": "OWASP",  # ← AGREGAR ESTA LÍNEA
            "XSS Detector": "OWASP",
            "CSRF Tester": "OWASP",
            "SSH Brute Force": "BRUTE_FORCE",
        }
        return category_map.get(tool_name, "UNKNOWN")

    def _process_vulnerabilities(
        self,
        vulnerabilities: list,
        tool_name: str,
        target: str,
        mitre_tech_id: str,
        mitre_tech_name: str,
        mitre_tactic: str,
    ):
        """
        Procesar y guardar vulnerabilidades encontradas
        """
        for vuln in vulnerabilities:
            # Calcular CVSS si no está presente
            cvss_score = vuln.get("cvss_score")
            if not cvss_score:
                # Determinar parámetros basados en severidad
                severity = vuln.get("severity", "Medium")
                if severity == "Critical":
                    cvss_score, calc_severity, cvss_vector = SimpleCVSS.quick_score(
                        network_accessible=True,
                        requires_auth=False,
                        user_interaction=False,
                    )
                elif severity == "High":
                    cvss_score, calc_severity, cvss_vector = SimpleCVSS.quick_score(
                        network_accessible=True,
                        requires_auth=False,
                        user_interaction=True,
                    )
                else:
                    cvss_score, calc_severity, cvss_vector = SimpleCVSS.quick_score(
                        network_accessible=False,
                        requires_auth=True,
                        user_interaction=True,
                    )
            else:
                severity = vuln.get("severity", "Medium")
                cvss_vector = vuln.get("cvss_vector", "N/A")

            # Crear vulnerabilidad en BD
            db_manager.create_vulnerability(
                project_id=self.project_id,
                title=vuln.get("title", "Vulnerability"),
                description=vuln.get("description", ""),
                target=vuln.get("affected_url")
                or vuln.get("affected_target")
                or target,
                port=vuln.get("port"),
                service=vuln.get("service"),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=severity,
                cve_id=vuln.get("cve"),
                cwe_id=vuln.get("cwe"),
                proof_of_concept=vuln.get("evidence"),
                remediation=vuln.get("remediation"),
                mitre_technique_id=mitre_tech_id,
                mitre_technique_name=mitre_tech_name,
                mitre_tactic=mitre_tactic,
            )
