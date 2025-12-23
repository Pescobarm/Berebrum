import requests
from core.mcp_protocol import MCPTool
import os


class ParamMiner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="Parameter Miner",
            description="Descubrimiento de parámetros GET usando diccionario",
            mitre_id="T1595",  # Active Scanning
            project_id=project_id,
            guardian=guardian,
        )
        self.wordlist_path = os.path.join("data", "wordlists", "parametros.txt")

    def _load_params(self):
        if not os.path.exists(self.wordlist_path):
            return ["id", "cat", "page", "search", "file"]  # Fallback
        with open(self.wordlist_path, "r", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]

    def _execute(self, target_url):
        # target_url debe ser un archivo, ej: http://site.com/index.php
        params_list = self._load_params()

        # Limitamos para demo (quitar límite en prod)
        params_list = params_list[:20]

        print(f"[*] ⛏️ Buscando parámetros ocultos en {target_url}...")
        print(f"    📚 Diccionario: parametros.txt ({len(params_list)} palabras)")

        found_params = []

        # 1. Obtener la longitud de respuesta base (sin params) para comparar
        try:
            base_res = requests.get(target_url, timeout=3)
            base_len = len(base_res.text)
        except:
            return {"status": "ERROR", "msg": "Target inalcanzable"}

        for param in params_list:
            # Probamos inyectando una marca
            test_url = f"{target_url}?{param}=BEREBRUM_TEST"

            try:
                res = requests.get(test_url, timeout=2)

                # HEURÍSTICA SIMPLE:
                # Si el tamaño de la respuesta cambia significativamente O
                # si nuestra marca se refleja en el texto.
                if len(res.text) != base_len or "BEREBRUM_TEST" in res.text:
                    diff = len(res.text) - base_len
                    if abs(diff) > 50:  # Ignorar cambios pequeños (ruido)
                        print(
                            f"    💎 Parámetro encontrado: ?{param}= (Diff: {diff} bytes)"
                        )

                        full_vuln_url = f"{target_url}?{param}=1"
                        found_params.append(full_vuln_url)

                        self.save_finding(
                            title=f"Hidden Parameter: {param}",
                            target=target_url,
                            evidence=f"URL: {full_vuln_url}\nRespuesta base: {base_len}b | Con param: {len(res.text)}b",
                            severity="Info",
                            cvss_score=0.0,
                        )
            except:
                pass

        return {"status": "FINISHED", "found_urls": found_params}
