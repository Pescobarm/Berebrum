import socket
from core.mcp_protocol import MCPTool


class BannerGrabber(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="Banner Grabber",
            description="Captura de banners de servicios (Fingerprinting)",
            mitre_id="T1046",
            project_id=project_id,
            guardian=guardian,
        )

    def _execute(self, target_ip, ports=[21, 22, 23, 25, 80, 443, 3306]):
        print(f"[*] 🏷️ Obteniendo banners de {target_ip}...")
        results = {}

        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((target_ip, port))

                if result == 0:
                    # Intentamos recibir datos
                    try:
                        # Para HTTP hay que enviar algo primero, para SSH/FTP suelen saludar ellos
                        if port in [80, 8080, 443]:
                            s.send(b"HEAD / HTTP/1.0\r\n\r\n")

                        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                        if banner:
                            print(
                                f"    Port {port}: {banner[:50]}..."
                            )  # Mostrar solo el inicio
                            results[port] = banner

                            self.save_finding(
                                title=f"Service Banner: Port {port}",
                                target=f"{target_ip}:{port}",
                                evidence=f"Banner Raw:\n{banner}",
                                severity="Info",
                                cvss_score=0.0,
                            )
                    except:
                        pass
                s.close()
            except:
                pass

        return {"status": "FINISHED", "banners": results}
