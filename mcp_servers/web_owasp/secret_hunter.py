import requests
import re
from core.safety import ScopeGuardian


class SecretHunter:
    def __init__(self, project_id, guardian: ScopeGuardian):
        self.project_id = project_id
        self.guardian = guardian

        # Patrones de REGEX para secretos comunes
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
        }

    def run(self, target_url):
        if not self.guardian.is_safe(target_url):
            return "❌ Target out of scope."

        print(f"🕵️ Buscando secretos en {target_url}...")
        results = []

        try:
            # 1. Obtener el HTML principal
            response = requests.get(target_url, timeout=10, verify=False)  # nosec
            content = response.text

            # 2. Buscar también en archivos .js vinculados (básico)
            js_files = re.findall(r'src=["\'](.*?\.js)["\']', content)

            targets_content = [(target_url, content)]

            # Descargar hasta 3 JS para no saturar
            for js in js_files[:3]:
                if not js.startswith("http"):
                    # Construir url absoluta si es relativa
                    base = target_url.rstrip("/")
                    js_url = f"{base}/{js.lstrip('/')}"
                else:
                    js_url = js

                try:
                    js_res = requests.get(js_url, timeout=5)
                    targets_content.append((js_url, js_res.text))
                except:
                    pass

            # 3. Analizar todo
            found_secrets = False
            for url, text in targets_content:
                for name, pattern in self.patterns.items():
                    matches = re.findall(pattern, text)
                    if matches:
                        found_secrets = True
                        # Ofuscamos el secreto para el reporte
                        safe_matches = [m[:4] + "..." + m[-4:] for m in matches]
                        finding = {
                            "location": url,
                            "type": name,
                            "count": len(matches),
                            "samples": safe_matches,
                        }
                        results.append(finding)

            if not found_secrets:
                return "✅ Limpio. No se encontraron API Keys expuestas."

            # Formatear salida
            out = "🚨 SECRETOS ENCONTRADOS:\n"
            for r in results:
                out += f"- [{r['type']}] en {r['location']}: {r['samples']}\n"
            return out

        except Exception as e:
            return f"❌ Error en SecretHunter: {str(e)}"
