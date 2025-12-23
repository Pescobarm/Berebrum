import requests
from core.mcp_protocol import MCPTool


class CMSScanner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="CMS Fingerprinter",
            description="Identifica Gestores de Contenido (WordPress, Joomla, Drupal)",
            mitre_id="T1595.002",
            project_id=project_id,
            guardian=guardian,
        )
        self.signatures = {
            "WordPress": ["wp-content", "wp-includes", 'generator" content="WordPress'],
            "Joomla": ["/templates/", 'generator" content="Joomla'],
            "Drupal": ["Drupal", "sites/default/files"],
            "Magento": ["Mage.Cookies", "skin/frontend"],
            "Shopify": ["cdn.shopify.com"],
        }

    def _execute(self, target_url):
        if not target_url.startswith("http"):
            target_url = f"http://{target_url}"

        print(f"[*] 🔎 Analizando CMS en: {target_url} ...")

        detected = []

        fake_browser = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        try:
            res = requests.get(target_url, timeout=10, headers=fake_browser)
            html = res.text
            headers = str(res.headers)

            # Chequeo de firmas en HTML y Headers
            for cms, sigs in self.signatures.items():
                for sig in sigs:
                    if sig in html or sig in headers:
                        if cms not in detected:
                            detected.append(cms)
                            print(f"    🎯 CMS Detectado: {cms}")

            # Chequeo específico de rutas (Ruidoso pero efectivo)
            if not detected:
                # Intento rápido de admin panels comunes
                checks = {
                    "WordPress": "/wp-login.php",
                    "Joomla": "/administrator/",
                    "Drupal": "/user/login",
                }
                for cms, path in checks.items():
                    try:
                        full_url = f"{target_url.rstrip('/')}{path}"
                        r2 = requests.get(full_url, timeout=3)
                        if r2.status_code == 200 and (
                            "login" in r2.text.lower() or "admin" in r2.text.lower()
                        ):
                            detected.append(f"{cms} (Path confirmed)")
                            print(f"    🎯 CMS Detectado por ruta: {cms}")
                    except:
                        pass

            if detected:
                self.save_finding(
                    title=f"Technology Stack: {', '.join(detected)}",
                    target=target_url,
                    evidence=f"CMS Identificados: {detected}",
                    severity="Info",
                    cvss_score=0.0,
                )
                return {"status": "DETECTED", "cms": detected}
            else:
                print("    🤷 No se identificó un CMS conocido.")
                return {"status": "UNKNOWN"}

        except Exception as e:
            return {"status": "ERROR", "msg": str(e)}
