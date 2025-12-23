import os
from pathlib import Path

# Definición de la estructura basada en el Roadmap
structure = {
    "config": ["__init__.py", "settings.py", "definitions.py"],
    "database": ["__init__.py", "models.py", "session.py"],
    "core": ["__init__.py", "safety.py", "dictionary_man.py", "mcp_protocol.py"],
    "mcp_servers": ["__init__.py"],
    "mcp_servers/reconnaissance": ["__init__.py"],
    "mcp_servers/web_owasp": ["__init__.py"],
    "mcp_servers/brute_force": ["__init__.py"],
    "mcp_servers/post_exploitation": ["__init__.py"],
    "mcp_servers/mobile": ["__init__.py"],
    "mcp_servers/utils": ["__init__.py"],
    "llm_engine": ["__init__.py"],
    "outputs": [],
    "data/wordlists": [],  # Aquí se clonarán los repos
}

def create_structure():
    base_path = Path.cwd()
    print(f"[*] Generando arquitectura NeuroStrike en: {base_path}")

    for folder, files in structure.items():
        # Crear carpeta
        folder_path = base_path / folder
        folder_path.mkdir(parents=True, exist_ok=True)
        print(f"   [+] Carpeta creada: {folder}")

        # Crear archivos dentro de la carpeta
        for file in files:
            file_path = folder_path / file
            if not file_path.exists():
                file_path.touch()
                print(f"      - Archivo creado: {file}")

    # Archivos raíz
    root_files = ["main.py", "requirements.txt", ".env", "Dockerfile", "docker-compose.yml", "ROADMAP_NEUROSTRIKE.md"]
    for rf in root_files:
        (base_path / rf).touch()
        print(f"   [+] Archivo Raíz: {rf}")

    print("\n[OK] Estructura finalizada exitosamente.")

if __name__ == "__main__":
    create_structure()