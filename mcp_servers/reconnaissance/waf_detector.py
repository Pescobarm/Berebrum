import requests
from core.mcp_protocol import MCPTool


class WafDetector(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="WAF Detector",
            description="Detecta firewalls web (Cloudflare, AWS, Akamai) mediante firmas y comportamiento.",
            mitre_id="T1595.002",  # Active Scanning
            project_id=project_id,
            guardian=guardian,
        )
        # Diccionario de Firmas (Huellas digitales de los WAFs)
        self.waf_signatures = {
            "Cloudflare": [
                "cf-ray",
                "__cfduid",
                "cf-cache-status",
                "server: cloudflare",
            ],
            "AWS WAF": ["x-amz-cf-id", "x-amzn-requestid", "awselb"],
            "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
            "Imperva": ["x-cdn", "incap_ses", "_incap_"],
            "F5 BIG-IP": ["bigipserver", "ts01"],
            "Sucuri": ["sucuri-cloudproxy", "x-sucuri-id"],
        }

    def _execute(self, target_url):
        # 1. Normalización de URL
        if not target_url.startswith("http"):
            target_url = f"http://{target_url}"

        print(f"[*] 🛡️  Iniciando escaneo de WAF contra: {target_url}")

        detected_wafs = []
        headers = {}

        try:
            # --- FASE 1: Análisis Pasivo (Headers y Cookies) ---
            res = requests.get(
                target_url, timeout=5, headers={"User-Agent": "Berebrum-Scanner/1.0"}
            )

            # Convertimos todo a minúsculas para facilitar la búsqueda
            headers_str = str(res.headers).lower()
            cookies_str = str(res.cookies.get_dict()).lower()

            for waf_name, sigs in self.waf_signatures.items():
                for sig in sigs:
                    # Buscamos la firma en los headers o cookies
                    if sig in headers_str or sig in cookies_str:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            print(
                                f"    🚨 WAF IDENTIFICADO: {waf_name} (Firma encontrada: {sig})"
                            )

            # --- FASE 2: Análisis Activo (Provocación) ---
            # Si no hemos detectado nada, intentamos provocar al WAF
            if not detected_wafs:
                print("    ⚡ Intentando provocación activa...")
                provoke_url = f"{target_url}?id=<script>alert('WAF_TEST')</script>"
                res_block = requests.get(provoke_url, timeout=5)

                # Si la página normal es 200 OK, pero el ataque devuelve 403/406, algo nos frenó.
                if res.status_code == 200 and res_block.status_code in [403, 406]:
                    detected_wafs.append("Generic WAF (Behavioral)")
                    print(
                        f"    🚨 WAF Genérico detectado por bloqueo de comportamiento (Status {res_block.status_code})."
                    )

        except Exception as e:
            return {"status": "ERROR", "msg": f"Error de conexión: {str(e)}"}

        # --- REPORTE Y GUARDADO ---
        if detected_wafs:
            waf_list = ", ".join(detected_wafs)
            self.save_finding(
                title=f"Defense Detected: {waf_list}",
                target=target_url,
                evidence=f"Firewalls detectados: {waf_list}\nHeaders analizados.",
                severity="Info",
                cvss_score=0.0,
            )
            return {"status": "DETECTED", "wafs": detected_wafs}
        else:
            print("    ✅ No se detectó WAF. Tráfico directo al servidor.")
            return {"status": "CLEAN", "wafs": []}
