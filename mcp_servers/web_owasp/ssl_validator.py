import ssl
import socket
from urllib.parse import urlparse
from core.safety import ScopeGuardian


class SSLValidator:
    def __init__(self, project_id, guardian: ScopeGuardian):
        self.project_id = project_id
        self.guardian = guardian

    def run(self, target_url):
        # Limpieza de URL para obtener solo hostname y puerto
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        port = parsed.port or 443

        if not self.guardian.is_safe(hostname):
            return "❌ Target out of scope."

        print(f"🔒 Analizando SSL/TLS en {hostname}...")

        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeermech()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Análisis simple
                    risk = "LOW"
                    msg = "Configuración Aceptable"

                    if version in ["TLSv1", "TLSv1.1"]:
                        risk = "HIGH"
                        msg = "Protocolo obsoleto detectado (Vulnerable a POODLE/BEAST)"

                    return f"""
🔐 REPORTE SSL:
- Protocolo: {version}
- Cifrado: {cipher[0]} ({cipher[2]} bits)
- Riesgo: {risk}
- Estado: {msg}
"""
        except Exception as e:
            return f"❌ Error SSL: {e} (¿El puerto 443 está abierto?)"
