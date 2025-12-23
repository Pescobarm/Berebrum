import subprocess
import defusedxml.ElementTree as ET
import shutil
import os
from core.mcp_protocol import MCPTool


class NmapScanner(MCPTool):
    def __init__(self, project_id, guardian, parent_id=None):
        super().__init__(
            name="Nmap Service Scan",
            description="Escaneo de servicios y versiones (Top 1000 puertos)",
            mitre_id="T1046",  # Network Service Discovery
            project_id=project_id,
            guardian=guardian,
            parent_action_id=parent_id,
        )

    def _get_nmap_command(self):
        """Busca el ejecutable de Nmap en el sistema o en rutas comunes"""
        # 1. Intentar encontrarlo en el PATH global
        nmap_exe = shutil.which("nmap")

        # 2. Si no está en el PATH, buscar en la ruta estándar de Windows (x86)
        if not nmap_exe:
            default_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
            if os.path.exists(default_path):
                # Importante: Comillas para manejar espacios en "Program Files"
                nmap_exe = f'"{default_path}"'

        return nmap_exe

    def _execute(self, target, arguments="-sV -T4 --open"):
        """
        Ejecuta Nmap y devuelve una lista estructurada de puertos/servicios.
        """
        # 1. Localizar el ejecutable
        nmap_cmd = self._get_nmap_command()

        if not nmap_cmd:
            return {
                "status": "ERROR",
                "details": "CRÍTICO: No se encontró nmap.exe. Instálalo o agrégalo al PATH.",
            }

        # 2. Construir el comando (Forzamos salida XML -oX -)
        command = f"{nmap_cmd} {arguments} -oX - {target}"
        print(f"    🛠️ Debug: Ejecutando comando -> {command}")

        try:
            # Ejecutar proceso
            process = subprocess.run(
                command, shell=True, capture_output=True, text=True
            )# nosec
            # ... código siguiente ...

            # Nmap a veces retorna warnings en stderr pero funciona, así que verificamos stdout
            if not process.stdout.strip() and process.stderr:
                raise Exception(f"Nmap falló: {process.stderr}")

            # Parsear el XML resultante
            return self._parse_nmap_xml(process.stdout, target)

        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _parse_nmap_xml(self, xml_content, target):
        """Convierte el XML de Nmap a JSON limpio y guarda Findings"""
        try:
            root = ET.fromstring(xml_content)
            open_ports = []

            for host in root.findall("host"):
                for ports in host.findall("ports"):
                    for port in ports.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        service_item = port.find("service")
                        service_name = (
                            service_item.get("name")
                            if service_item is not None
                            else "unknown"
                        )
                        product = (
                            service_item.get("product")
                            if service_item is not None
                            else ""
                        )
                        version = (
                            service_item.get("version")
                            if service_item is not None
                            else ""
                        )

                        full_service = f"{service_name} {product} {version}".strip()

                        port_info = {
                            "port": port_id,
                            "protocol": protocol,
                            "service": full_service,
                        }
                        open_ports.append(port_info)

                        # GUARDAR HALLAZGO AUTOMÁTICAMENTE
                        self.save_finding(
                            title=f"Open Port {port_id}/{protocol}",
                            target=target,
                            evidence=f"Service detected: {full_service}",
                            severity="Low",
                            cvss_score=0.0,
                        )

            return {
                "status": "FINISHED",
                "host": target,
                "open_ports": open_ports,
                "total_open": len(open_ports),
            }
        except ET.ParseError:
            return {
                "status": "ERROR",
                "details": "No se pudo leer el XML de Nmap. Output corrupto o vacío.",
            }
