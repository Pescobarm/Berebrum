import requests
import os
from core.mcp_protocol import MCPTool


class DirScanner(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="Directory Fuzzer",
            description="Búsqueda de rutas usando wordlists (Diccionarios)",
            mitre_id="T1595",
            project_id=project_id,
            guardian=guardian,
        )
        # Aquí definimos qué diccionario usar por defecto.
        # Viendo tu imagen, 'common.txt' es un buen punto de partida equilibrado.
        self.wordlist_path = os.path.join("data", "wordlists", "common.txt")

    def _load_wordlist(self):
        """Carga las palabras del archivo manejando errores de lectura"""
        if not os.path.exists(self.wordlist_path):
            print(f"    ⚠️ Error: No se encontró el diccionario en {self.wordlist_path}")
            # Fallback de emergencia si borras la carpeta data
            return ["admin", "login", "robots.txt", "dashboard", "config"]

        words = []
        try:
            # Intentamos leer con utf-8 primero
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"    ⚠️ Error leyendo diccionario: {e}")

        return words

    def _execute(self, target_domain):
        """
        target_domain: El dominio limpio (ej: scanme.nmap.org)
        """
        # 1. Normalizar URL (Añadir http si falta)
        if not target_domain.startswith("http"):
            base_url = f"http://{target_domain}"
        else:
            base_url = target_domain

        # Quitamos la barra final para evitar dobles barras (//)
        base_url = base_url.rstrip("/")

        # 2. Cargar Diccionario
        words = self._load_wordlist()

        # Limite de seguridad: Si el diccionario es GIGANTE (ej: 1 millon de lineas),
        # podríamos querer limitarlo para pruebas rápidas.
        # words = words[:1000] # Descomenta para limitar a los primeros 1000

        print(f"[*] 📂 Iniciando Fuzzing en {base_url}")
        print(f"    📚 Diccionario: {self.wordlist_path}")
        print(f"    🔢 Total palabras: {len(words)}")

        found_urls = []

        # 3. Iterar (Fuzzing)
        try:
            for word in words:
                target_url = f"{base_url}/{word}"

                try:
                    # Timeout bajo (2s) para agilidad
                    res = requests.get(target_url, timeout=2, allow_redirects=False)

                    # Filtramos códigos de estado
                    if res.status_code in [200, 301, 302, 403, 500]:
                        status_icon = "✅" if res.status_code == 200 else "⚠️"

                        # Imprimir en consola limpio
                        print(f"    {status_icon} [{res.status_code}] Found: /{word}")

                        # Guardar Hallazgo en Base de Datos
                        self.save_finding(
                            title=f"Path Discovered: /{word}",
                            target=base_url,
                            evidence=f"URL: {target_url}\nStatus: {res.status_code}",
                            severity="Info",
                            cvss_score=0.0,
                        )
                        found_urls.append(target_url)

                except requests.RequestException:
                    pass  # Ignorar fallos de conexión

        except KeyboardInterrupt:
            print("\n    🛑 Deteniendo escaneo por usuario...")

        return {
            "status": "FINISHED",
            "total_scanned": len(words),
            "found_urls": found_urls,
        }
