import requests
import json
from core.mcp_protocol import MCPTool


class SubdomainEnum(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="Subdomain Enumerator",
            description="Busca subdominios usando Certificate Transparency Logs (crt.sh)",
            mitre_id="T1596",
            project_id=project_id,
            guardian=guardian,
        )

    def _execute(self, domain):
        print(f"[*] 🌐 Buscando subdominios para: {domain} ...")

        # Limpieza básica del dominio
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

        subdomains = set()

        try:
            # Consultamos crt.sh
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            res = requests.get(url, timeout=60)

            if res.status_code == 200:
                data = res.json()
                for entry in data:
                    name_value = entry["name_value"]
                    # A veces vienen multilineas
                    found_subs = name_value.split("\n")
                    for sub in found_subs:
                        if "*" not in sub and sub.endswith(domain):
                            subdomains.add(sub)

            # Ordenamos resultados
            sorted_subs = sorted(list(subdomains))

            print(f"    ✅ Encontrados {len(sorted_subs)} subdominios únicos.")

            if sorted_subs:
                # Guardamos evidencia
                evidence_text = "\n".join(sorted_subs)
                self.save_finding(
                    title=f"Subdomains Found for {domain}",
                    target=domain,
                    evidence=evidence_text,
                    severity="Info",
                    cvss_score=0.0,
                )

                # Mostrar en consola los primeros 10
                for s in sorted_subs[:10]:
                    print(f"      - {s}")
                if len(sorted_subs) > 10:
                    print(f"      ... y {len(sorted_subs)-10} más.")

                return {"status": "SUCCESS", "subdomains": sorted_subs}
            else:
                print("    ⚠️ No se encontraron subdominios (o crt.sh no tiene datos).")
                return {"status": "EMPTY"}

        except Exception as e:
            print(f"    ❌ Error conectando con crt.sh: {e}")
            return {"status": "ERROR", "msg": str(e)}
