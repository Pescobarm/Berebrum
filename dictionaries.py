"""
Dictionary Manager v1.0
Gestor centralizado de diccionarios para pentesting
Auto-descarga desde hackingyseguridad/diccionarios
"""

import os
import requests
from pathlib import Path
from typing import List, Optional
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DictionaryManager:
    """
    Gestor de diccionarios para herramientas de pentesting
    """

    def __init__(self, cache_dir: str = "tools/dictionaries"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Base URL del repositorio
        self.base_url = (
            "https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master"
        )

        # Mapeo de diccionarios disponibles
        self.dictionaries = {
            # Subdominios
            "subdominios": {
                "filename": "subdominios.txt",
                "url": f"{self.base_url}/subdominios.txt",
                "description": "Lista de subdominios comunes (1M+ entradas)",
                "max_lines": 100000,  # Limitar para performance
            },
            "subdominios_small": {
                "filename": "subdominios_small.txt",
                "url": f"{self.base_url}/subdominios.txt",
                "description": "Lista reducida de subdominios (10K entradas)",
                "max_lines": 10000,
            },
            # Directorios
            "directorios": {
                "filename": "directorios.txt",
                "url": f"{self.base_url}/directorios.txt",
                "description": "Lista de directorios web comunes",
                "max_lines": 50000,
            },
            "directorios_small": {
                "filename": "directorios_small.txt",
                "url": f"{self.base_url}/directorios.txt",
                "description": "Lista reducida de directorios (5K entradas)",
                "max_lines": 5000,
            },
            # Usuarios
            "usuarios": {
                "filename": "usuarios.txt",
                "url": f"{self.base_url}/usuarios.txt",
                "description": "Lista de usuarios comunes",
                "max_lines": 10000,
            },
            # Passwords
            "passwords": {
                "filename": "passwords.txt",
                "url": f"{self.base_url}/passwords.txt",
                "description": "Lista de contraseñas comunes",
                "max_lines": 100000,
            },
            "passwords_small": {
                "filename": "passwords_small.txt",
                "url": f"{self.base_url}/passwords.txt",
                "description": "Lista reducida de contraseñas (10K)",
                "max_lines": 10000,
            },
            # Parámetros
            "parametros": {
                "filename": "parametros.txt",
                "url": f"{self.base_url}/parametros.txt",
                "description": "Lista de parámetros web comunes",
                "max_lines": 5000,
            },
            # Extensiones
            "extensiones": {
                "filename": "extensiones.txt",
                "url": f"{self.base_url}/extensiones.txt",
                "description": "Lista de extensiones de archivo",
                "max_lines": 1000,
            },
            # Puertos
            "puertos": {
                "filename": "puertos.txt",
                "url": f"{self.base_url}/puertos.txt",
                "description": "Lista de puertos comunes",
                "max_lines": 1000,
            },
        }

    def get_dictionary(self, dict_name: str, force_download: bool = False) -> List[str]:
        """
        Obtiene un diccionario (descarga si es necesario)

        Args:
            dict_name: Nombre del diccionario
            force_download: Forzar descarga aunque exista

        Returns:
            Lista de entradas del diccionario
        """
        if dict_name not in self.dictionaries:
            raise ValueError(
                f"Diccionario '{dict_name}' no disponible. Disponibles: {list(self.dictionaries.keys())}"
            )

        dict_info = self.dictionaries[dict_name]
        cache_path = self.cache_dir / dict_info["filename"]

        # Verificar si existe en cache
        if cache_path.exists() and not force_download:
            return self._load_from_cache(cache_path, dict_info["max_lines"])

        # Descargar
        print(f"[*] Descargando diccionario: {dict_name}")
        print(f"[*] {dict_info['description']}")
        print(f"[*] URL: {dict_info['url']}")

        try:
            entries = self._download_dictionary(
                dict_info["url"], cache_path, dict_info["max_lines"]
            )
            print(f"[✓] Descargado: {len(entries)} entradas")
            return entries

        except Exception as e:
            print(f"[!] Error al descargar: {str(e)}")

            # Fallback: usar diccionario embebido básico
            print(f"[*] Usando diccionario básico embebido...")
            return self._get_fallback_dictionary(dict_name)

    def _download_dictionary(
        self, url: str, cache_path: Path, max_lines: int
    ) -> List[str]:
        """Descarga un diccionario desde GitHub"""

        response = requests.get(url, timeout=30, verify=False, stream=True)
        response.raise_for_status()

        entries = []
        lines_read = 0

        # Leer línea por línea (eficiente para archivos grandes)
        for line in response.iter_lines(decode_unicode=True):
            if not line or line.startswith("#"):
                continue

            entries.append(line.strip())
            lines_read += 1

            if lines_read >= max_lines:
                break

        # Guardar en cache
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write("\n".join(entries))

        return entries

    def _load_from_cache(self, cache_path: Path, max_lines: int) -> List[str]:
        """Carga diccionario desde cache"""

        entries = []

        with open(cache_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break

                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)

        return entries

    def _get_fallback_dictionary(self, dict_name: str) -> List[str]:
        """
        Diccionarios básicos embebidos como fallback
        Si falla la descarga de GitHub
        """

        fallbacks = {
            "subdominios": [
                "www",
                "mail",
                "ftp",
                "webmail",
                "smtp",
                "pop",
                "ns1",
                "ns2",
                "admin",
                "portal",
                "blog",
                "api",
                "dev",
                "staging",
                "test",
                "vpn",
                "remote",
                "secure",
                "static",
                "cdn",
            ],
            "subdominios_small": [
                "www",
                "mail",
                "ftp",
                "admin",
                "api",
                "dev",
                "test",
                "blog",
                "portal",
                "secure",
            ],
            "directorios": [
                "admin",
                "administrator",
                "login",
                "panel",
                "wp-admin",
                "wp-content",
                "uploads",
                "images",
                "css",
                "js",
                "api",
                "backup",
                "db",
                "config",
                "include",
                "includes",
                "lib",
                "temp",
                "tmp",
                "test",
            ],
            "directorios_small": [
                "admin",
                "login",
                "panel",
                "api",
                "uploads",
                "backup",
                "config",
                "test",
                "wp-admin",
                "phpmyadmin",
            ],
            "usuarios": [
                "admin",
                "administrator",
                "root",
                "user",
                "test",
                "guest",
                "postgres",
                "mysql",
                "oracle",
                "ftp",
            ],
            "passwords": [
                "admin",
                "password",
                "123456",
                "12345678",
                "root",
                "toor",
                "test",
                "guest",
                "Pass123",
                "Admin123",
            ],
            "passwords_small": [
                "admin",
                "password",
                "123456",
                "root",
                "test",
            ],
            "parametros": [
                "id",
                "page",
                "file",
                "cat",
                "cmd",
                "exec",
                "query",
                "search",
                "keyword",
                "lang",
                "redirect",
                "url",
                "view",
                "template",
                "action",
                "download",
                "upload",
                "path",
                "dir",
                "folder",
            ],
            "extensiones": [
                "php",
                "asp",
                "aspx",
                "jsp",
                "html",
                "htm",
                "js",
                "txt",
                "xml",
                "json",
                "bak",
                "old",
                "zip",
                "tar",
                "gz",
            ],
            "puertos": [
                "21",
                "22",
                "23",
                "25",
                "53",
                "80",
                "110",
                "143",
                "443",
                "445",
                "3306",
                "3389",
                "5432",
                "8080",
                "8443",
            ],
        }

        return fallbacks.get(dict_name, [])

    def list_dictionaries(self):
        """Lista diccionarios disponibles"""
        print("\n" + "=" * 70)
        print("DICCIONARIOS DISPONIBLES")
        print("=" * 70)

        for name, info in self.dictionaries.items():
            cache_path = self.cache_dir / info["filename"]
            status = "✅ Cached" if cache_path.exists() else "⬇️  Download"

            print(f"\n{status} {name}")
            print(f"  {info['description']}")
            print(f"  Max entries: {info['max_lines']:,}")

        print("\n" + "=" * 70)

    def clear_cache(self):
        """Limpia cache de diccionarios"""
        import shutil

        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            print("[✓] Cache limpiado")


# Instancia global para uso simple
_manager = DictionaryManager()


def get_dictionary(dict_name: str, force_download: bool = False) -> List[str]:
    """
    Función wrapper para uso simple

    Ejemplo:
        subdominios = get_dictionary('subdominios_small')
        directorios = get_dictionary('directorios')
    """
    return _manager.get_dictionary(dict_name, force_download)


def list_dictionaries():
    """Lista diccionarios disponibles"""
    _manager.list_dictionaries()


def clear_cache():
    """Limpia cache"""
    _manager.clear_cache()


# Test
if __name__ == "__main__":
    # Listar disponibles
    list_dictionaries()

    print("\n" + "=" * 70)
    print("TEST: DESCARGANDO DICCIONARIO")
    print("=" * 70)

    # Probar descarga
    subdominios = get_dictionary("subdominios_small")

    print(f"\n[✓] Obtenidos {len(subdominios)} subdominios")
    print(f"[*] Primeros 10:")
    for sub in subdominios[:10]:
        print(f"    - {sub}")
