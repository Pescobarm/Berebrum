import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.mcp_protocol import MCPTool


class SSTIScanner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="SSTI Scanner",
            description="Server-Side Template Injection (Math Test)",
            mitre_id="T1190",
            project_id=project_id,
            guardian=guardian,
        )
        # Payloads matemáticos para detectar diferentes motores
        self.payloads = [
            "{{7*7}}",  # Jinja2 / Twig
            "${7*7}",  # Smarty
            "<%= 7*7 %>",  # ERB
            "#{7*7}",  # Velocity
            "{{7*'7'}}",  # Twig specific
        ]

    def _execute(self, target_url):
        print(f"[*] 🧠 Buscando SSTI en {target_url}...")
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            return {"status": "SKIPPED", "msg": "No params"}

        for param, values in params.items():
            for payload in self.payloads:
                # Inyección
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                attack_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    )
                )

                try:
                    res = requests.get(attack_url, timeout=3)
                    # La magia: Si enviamos 7*7 y recibimos 49
                    if "49" in res.text and "7*7" not in res.text:
                        print(f"    🔥 SSTI DETECTADO en '{param}'!")
                        print(f"       Payload: {payload} -> Renderizó: 49")

                        self.save_finding(
                            title=f"SSTI Vulnerability in {param}",
                            target=target_url,
                            evidence=f"Payload usado: {payload}\nResultado esperado: 49\nURL: {attack_url}\n\nPara replicar: curl '{attack_url}'",
                            severity="Critical",  # RCE Potencial
                            cvss_score=9.8,
                        )
                        return {
                            "status": "VULNERABLE",
                            "param": param,
                            "payload": payload,
                        }
                except:
                    pass

        return {"status": "CLEAN"}
