import os
import git
from pathlib import Path
from config.settings import WORDLISTS_DIR, DICT_REPO_URL
from config.definitions import WORDLIST_MAP


class DictionaryManager:
    def __init__(self):
        self.repo_path = WORDLISTS_DIR
        self._ensure_repo()

    def _ensure_repo(self):
        """Verifica si los diccionarios existen, si no, los descarga."""
        # Verificamos si existe la carpeta .git dentro de wordlists
        git_dir = self.repo_path / ".git"

        if not git_dir.exists():
            print(
                f"[*] 📦 Diccionarios no encontrados. Descargando arsenal de: {DICT_REPO_URL}"
            )
            print("    Esto puede tardar unos minutos dependiendo de tu conexión...")
            try:
                git.Repo.clone_from(DICT_REPO_URL, self.repo_path)
                print("[+] ✅ Diccionarios descargados correctamente.")
            except Exception as e:
                print(f"[!] ❌ Error crítico clonando diccionarios: {e}")
        else:
            print("[*] 📚 Diccionarios detectados y listos.")

    def get_path(self, key):
        """Obtiene la ruta absoluta de un diccionario por su CLAVE"""
        if key not in WORDLIST_MAP:
            raise KeyError(f"La clave '{key}' no existe en definitions.py")

        relative_path = WORDLIST_MAP[key]
        full_path = self.repo_path / relative_path

        if not full_path.exists():
            print(f"[!] ADVERTENCIA: El archivo {full_path} no existe físicamente.")
            return None

        return full_path

    def get_payloads(self, key):
        """Generador que entrega líneas limpias una a una (ahorra memoria RAM)"""
        path = self.get_path(key)
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:  # Ignorar líneas vacías
                        yield line
        except Exception as e:
            print(f"[!] Error leyendo diccionario {key}: {e}")


# Instancia global para pruebas rápidas
if __name__ == "__main__":
    dm = DictionaryManager()
    # Prueba rápida: Leer las primeras 5 líneas de usuarios
    print("--- Prueba: 5 usuarios top ---")
    gen = dm.get_payloads("USER_TOP")
    for _ in range(5):
        print(next(gen))
