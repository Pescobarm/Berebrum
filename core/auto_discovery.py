import requests
import os


class AutoDiscovery:
    def __init__(self):
        self.common_files = os.path.join("data", "wordlists", "common.txt")
        self.params_file = os.path.join("data", "wordlists", "params.txt")

    def _get_protocol(self, domain):
        """Determina si es HTTP o HTTPS"""
        try:
            requests.get(f"https://{domain}", timeout=3)
            return f"https://{domain}"
        except:
            return f"http://{domain}"

    def _load_wordlist(self, filepath, default_list):
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return [l.strip() for l in f if l.strip()]
        return default_list

    def resolve_targets(self, input_target):
        """
        Transforma un dominio crudo en URLs con parámetros listos para ataque.
        """
        targets_ready = []

        # 1. Si el usuario ya dio una URL completa con parámetros, la devolvemos tal cual.
        if "?" in input_target and "=" in input_target:
            return [input_target]

        print(f"[*] 🕵️ Analizando estructura de: {input_target} ...")

        # 2. Definir Protocolo (HTTP/S) y Base
        if input_target.startswith("http"):
            base_url = input_target
        else:
            base_url = self._get_protocol(input_target)
            print(f"    ✅ Protocolo detectado: {base_url.split(':')[0]}")

        # 3. Descubrimiento de Archivos (Fase DirScanner simplificada)
        # Si el input ya tiene un archivo (ej: site.com/login.php), saltamos esto.
        paths_to_check = []
        if (
            ".php" in input_target
            or ".asp" in input_target
            or input_target.endswith("/")
        ):
            paths_to_check = [base_url]
        else:
            print("    📂 Buscando puntos de entrada (endpoints)...")
            files = self._load_wordlist(
                self.common_files, ["index.php", "admin.php", "login.php", "search.php"]
            )
            # Limitamos para velocidad
            files = files[:50]

            for f in files:
                url = (
                    f"{base_url}/{f}"
                    if not base_url.endswith("/")
                    else f"{base_url}{f}"
                )
                try:
                    res = requests.get(url, timeout=2)
                    if res.status_code == 200:
                        paths_to_check.append(url)
                except:
                    pass

        if not paths_to_check:
            # Fallback: Intentar atacar la raíz si no encontramos archivos
            paths_to_check = [base_url]
            print("    ⚠️ No se detectaron archivos comunes. Usando raíz.")

        # 4. Descubrimiento de Parámetros (Fase ParamMiner)
        print(
            f"    ⛏️ Buscando parámetros inyectables en {len(paths_to_check)} rutas..."
        )
        params = self._load_wordlist(
            self.params_file, ["id", "cat", "artist", "query", "search"]
        )
        # Limitamos para velocidad
        params = params[:30]

        for url in paths_to_check:
            # Obtenemos la longitud base para comparar
            try:
                base_len = len(requests.get(url, timeout=3).text)
            except:
                continue

            for p in params:
                # Probamos si el parámetro existe
                test_url = f"{url}?{p}=1"
                try:
                    res = requests.get(test_url, timeout=1)
                    # Si el tamaño cambia significativamente, el parámetro es real
                    if abs(len(res.text) - base_len) > 50:
                        print(f"    💎 Objetivo Encontrado: {test_url}")
                        targets_ready.append(test_url)
                except:
                    pass

        return targets_ready
