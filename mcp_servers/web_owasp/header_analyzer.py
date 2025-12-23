import requests
from core.mcp_protocol import MCPTool


class HeaderAnalyzer(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="HTTP Header Analyzer",
            description="Analiza cabeceras de seguridad faltantes o mal configuradas",
            mitre_id="T1592",  # Gather Victim Host Information
            project_id=project_id,
            guardian=guardian,
        )
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
        ]

    def _execute(self, target_url):
        print(f"[*] 🕵️ Analizando cabeceras HTTP de {target_url}...")

        try:
            response = requests.get(target_url, timeout=5)
            headers = response.headers
            missing = []

            # Verificar Server Header (Information Disclosure)
            if "Server" in headers:
                server_info = headers["Server"]
                self.save_finding(
                    title="Information Disclosure: Server Header",
                    target=target_url,
                    evidence=f"Server Header revela tecnología: {server_info}",
                    severity="Low",
                    cvss_score=2.0,
                )

            # Verificar Headers de Seguridad Faltantes
            for sec_header in self.security_headers:
                if sec_header not in headers:
                    missing.append(sec_header)
                    self.save_finding(
                        title=f"Missing Header: {sec_header}",
                        target=target_url,
                        evidence=f"El servidor no envió la cabecera {sec_header}",
                        severity="Low",
                        cvss_score=0.0,
                    )

            return {
                "status": "FINISHED",
                "missing_headers": missing,
                "server_version": headers.get("Server", "Unknown"),
            }

        except Exception as e:
            return {"status": "ERROR", "details": str(e)}
