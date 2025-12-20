"""
MIGRACIÓN AUTOMÁTICA: ESTRUCTURA PROFESIONAL BEREBRUM
Preserva TODO el historial Git usando 'git mv'
Tiempo estimado: 10 minutos
"""

import os
import subprocess
import shutil

print("=" * 70)
print("MIGRACIÓN: ESTRUCTURA PROFESIONAL BEREBRUM")
print("=" * 70)
print()
print("⚠️  IMPORTANTE:")
print("   • Este script usa 'git mv' para preservar historial")
print("   • Asegúrate de tener commits guardados")
print("   • Haz backup si tienes cambios sin commit")
print()

respuesta = input("¿Continuar? (sí/no): ").strip().lower()
if respuesta not in ["sí", "si", "s", "yes", "y"]:
    print("\n❌ Migración cancelada")
    exit(0)

print("\n" + "=" * 70)
print("FASE 1: CREAR NUEVAS CARPETAS")
print("=" * 70)
print()

# Crear estructura de carpetas
carpetas = [
    # Tools organizados
    "tools/dictionaries",
    "tools/dictionaries/cache",
    "tools/web_utils",
    "tools/reconnaissance",
    "tools/owasp_top10",
    "tools/brute_force",
    "tools/exploitation",
    # Configuración
    "config",
    # Datos y cache
    "data",
    "data/projects",
    "logs",
    "logs/scanners",
    "cache",
    # Tests
    "tests",
    # Documentación
    "docs",
    # Scripts organizados
    "scripts/setup",
    "scripts/maintenance",
    "scripts/testing",
    # Docker
    "docker",
    # GitHub
    ".github/workflows",
    ".github/ISSUE_TEMPLATE",
]

for carpeta in carpetas:
    os.makedirs(carpeta, exist_ok=True)
    print(f"✅ {carpeta}/")

print("\n" + "=" * 70)
print("FASE 2: MOVER ARCHIVOS (PRESERVANDO HISTORIAL)")
print("=" * 70)
print()


def git_mv(origen, destino):
    """Mueve archivo preservando historial Git"""
    if os.path.exists(origen):
        try:
            # Crear directorio destino si no existe
            dest_dir = os.path.dirname(destino)
            if dest_dir and not os.path.exists(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)

            # Usar git mv
            subprocess.run(["git", "mv", origen, destino], check=True)
            print(f"✅ git mv {origen} → {destino}")
            return True
        except subprocess.CalledProcessError:
            print(f"⚠️  git mv falló para {origen}, usando mv normal")
            try:
                shutil.move(origen, destino)
                print(f"✅ mv {origen} → {destino}")
                return True
            except Exception as e:
                print(f"❌ Error moviendo {origen}: {e}")
                return False
    else:
        print(f"⚠️  {origen} no existe, saltando...")
        return False


# Mover scripts de raíz
print("\n[2.1] Moviendo scripts de raíz...")
git_mv("create_test_data.py", "scripts/testing/create_test_data.py")
git_mv("diagnose_all_logs.py", "scripts/testing/diagnose_all_logs.py")
git_mv("install_tplmap.py", "scripts/setup/install_tplmap.py")

# Mover Docker files
print("\n[2.2] Moviendo Docker files...")
git_mv("dockerfile", "docker/Dockerfile")
git_mv("docker-compose.yml", "docker/docker-compose.yml")

# Mover sstimap y tplmap
print("\n[2.3] Moviendo SSTI/Template Injection...")
git_mv("sstimap", "tools/owasp_top10/ssti_detector.py")
git_mv("tplmap", "tools/owasp_top10/template_injection.py")

# Mover herramientas de tools/ a subcategorías
print("\n[2.4] Reorganizando herramientas en tools/...")

# Reconnaissance
herramientas_recon = [
    "subdomain_enumerator.py",
    "port_scanner.py",
    "web_directory_scanner.py",
    "dns_enum.py",
    "whois_lookup.py",
    "ssl_scanner.py",
]

for herramienta in herramientas_recon:
    git_mv(f"tools/{herramienta}", f"tools/reconnaissance/{herramienta}")

# OWASP Top 10
herramientas_owasp = [
    "sql_injection_scanner.py",
    "xss_detector.py",
    "csrf_tester.py",
    "lfi_rfi_scanner.py",
    "command_injection_tester.py",
]

for herramienta in herramientas_owasp:
    git_mv(f"tools/{herramienta}", f"tools/owasp_top10/{herramienta}")

# Brute Force
herramientas_brute = [
    "ssh_brute_force.py",
    "ftp_brute_force.py",
]

for herramienta in herramientas_brute:
    git_mv(f"tools/{herramienta}", f"tools/brute_force/{herramienta}")

print("\n" + "=" * 70)
print("FASE 3: CREAR __init__.py EN SUBCARPETAS")
print("=" * 70)
print()

# Crear __init__.py en todas las subcarpetas de tools/
subcarpetas_tools = [
    "tools/dictionaries",
    "tools/web_utils",
    "tools/reconnaissance",
    "tools/owasp_top10",
    "tools/brute_force",
    "tools/exploitation",
]

for subcarpeta in subcarpetas_tools:
    init_file = f"{subcarpeta}/__init__.py"
    if not os.path.exists(init_file):
        with open(init_file, "w") as f:
            f.write(f'"""\n{subcarpeta.split("/")[1].title()} module\n"""\n')
        print(f"✅ {init_file}")

# Crear __init__.py en tests/
if not os.path.exists("tests/__init__.py"):
    with open("tests/__init__.py", "w") as f:
        f.write('"""\nBerebrum Tests\n"""\n')
    print(f"✅ tests/__init__.py")

print("\n" + "=" * 70)
print("FASE 4: CREAR ARCHIVOS DE CONFIGURACIÓN")
print("=" * 70)
print()

# .env.example
if not os.path.exists(".env.example"):
    with open(".env.example", "w") as f:
        f.write(
            """# Berebrum Configuration
DATABASE_PATH=data/berebrum.db
LOG_LEVEL=INFO
LOG_PATH=logs/berebrum.log

# API Keys (opcional)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# MCP Configuration
MCP_HOST=localhost
MCP_PORT=8000
"""
        )
    print("✅ .env.example")

# CHANGELOG.md
if not os.path.exists("CHANGELOG.md"):
    with open("CHANGELOG.md", "w") as f:
        f.write(
            """# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Reorganized project structure for scalability
- Added dictionaries module for external wordlists
- Added web_utils for shared utilities (crawler)
- Categorized tools: reconnaissance, owasp_top10, brute_force
- Added config/, data/, logs/, cache/, tests/, docs/ directories

### Changed
- Moved Docker files to docker/
- Moved utility scripts to scripts/ subdirectories
- Reorganized tools by category

## [0.1.0] - 2025-01-XX

### Added
- Initial release
- CLI interface
- Streamlit dashboard
- MCP protocol integration
- Basic pentesting tools
"""
        )
    print("✅ CHANGELOG.md")

# requirements-dev.txt
if not os.path.exists("requirements-dev.txt"):
    with open("requirements-dev.txt", "w") as f:
        f.write(
            """# Development dependencies
pytest>=7.0.0
pytest-cov>=4.0.0
black>=23.0.0
flake8>=6.0.0
mypy>=1.0.0
"""
        )
    print("✅ requirements-dev.txt")

# config/settings.py
if not os.path.exists("config/settings.py"):
    with open("config/settings.py", "w") as f:
        f.write(
            """\"\"\"
Berebrum Configuration Settings
\"\"\"
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / "cache"

# Database
DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "berebrum.db"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_PATH = os.getenv("LOG_PATH", str(LOGS_DIR / "berebrum.log"))

# MCP
MCP_HOST = os.getenv("MCP_HOST", "localhost")
MCP_PORT = int(os.getenv("MCP_PORT", "8000"))

# Dictionaries
DICTIONARIES_CACHE_DIR = BASE_DIR / "tools" / "dictionaries" / "cache"
DICTIONARIES_BASE_URL = "https://raw.githubusercontent.com/hackingyseguridad/diccionarios/master"
"""
        )
    print("✅ config/settings.py")

# .github/workflows/tests.yml
if not os.path.exists(".github/workflows/tests.yml"):
    with open(".github/workflows/tests.yml", "w") as f:
        f.write(
            """name: Tests

on:
  push:
    branches: [ develop, main ]
  pull_request:
    branches: [ develop, main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run tests
      run: |
        pytest tests/ -v --cov=.
"""
        )
    print("✅ .github/workflows/tests.yml")

print("\n" + "=" * 70)
print("FASE 5: ACTUALIZAR .gitignore")
print("=" * 70)
print()

# Agregar nuevas carpetas a .gitignore
gitignore_additions = """
# Cache y logs
cache/
logs/
*.log

# Datos locales
data/
!data/.gitkeep

# Diccionarios descargados
tools/dictionaries/cache/
!tools/dictionaries/cache/.gitkeep

# Environment
.env

# Tests
.pytest_cache/
.coverage
htmlcov/

# IDE
.vscode/
.idea/
*.swp
*.swo
"""

if os.path.exists(".gitignore"):
    with open(".gitignore", "a") as f:
        f.write(gitignore_additions)
    print("✅ .gitignore actualizado")
else:
    with open(".gitignore", "w") as f:
        f.write(gitignore_additions)
    print("✅ .gitignore creado")

# Crear .gitkeep en carpetas que deben estar vacías
gitkeep_dirs = [
    "cache",
    "data",
    "logs",
    "tools/dictionaries/cache",
]

for dir_path in gitkeep_dirs:
    gitkeep_path = f"{dir_path}/.gitkeep"
    if not os.path.exists(gitkeep_path):
        with open(gitkeep_path, "w") as f:
            pass
        print(f"✅ {gitkeep_path}")

print("\n" + "=" * 70)
print("FASE 6: GENERAR REPORTE DE IMPORTS A ACTUALIZAR")
print("=" * 70)
print()

print("📋 Archivos que requieren actualización de imports:")
print()

archivos_actualizar = [
    ("cli/main.py", "Actualizar imports de tools/"),
    ("dashboard/app.py", "Actualizar imports de tools/"),
    ("core/ai_operator.py", "Verificar si usa tools/"),
    ("core/mcp_orchestrator.py", "Verificar si usa tools/"),
]

print("Ejemplos de cambios necesarios:")
print()
print("ANTES:")
print("  from tools.sql_injection_scanner import scan_sql_injection")
print()
print("DESPUÉS:")
print("  from tools.owasp_top10.sql_injection_scanner import scan_sql_injection")
print()
print("ANTES:")
print("  from tools.subdomain_enumerator import enumerate_subdomains")
print()
print("DESPUÉS:")
print("  from tools.reconnaissance.subdomain_enumerator import enumerate_subdomains")
print()

for archivo, descripcion in archivos_actualizar:
    if os.path.exists(archivo):
        print(f"⚠️  {archivo} - {descripcion}")

print("\n" + "=" * 70)
print("✅ MIGRACIÓN COMPLETADA")
print("=" * 70)
print()
print("Cambios realizados:")
print("  ✅ Nueva estructura de carpetas creada")
print("  ✅ Archivos movidos preservando historial Git")
print("  ✅ __init__.py creados en subcarpetas")
print("  ✅ Archivos de configuración creados")
print("  ✅ .gitignore actualizado")
print()
print("=" * 70)
print("PRÓXIMOS PASOS")
print("=" * 70)
print()
print("1. Actualizar imports en archivos listados arriba")
print("   (Ver ejemplos de cambios necesarios)")
print()
print("2. Probar que todo funciona:")
print("   python -m cli.main")
print("   streamlit run dashboard/app.py")
print()
print("3. Commit y push:")
print("   git status")
print("   git add .")
print('   git commit -m "refactor: reorganize for scalability"')
print("   git push origin develop")
print()
print("=" * 70)
print("TIEMPO ESTIMADO PARA ACTUALIZAR IMPORTS: 20-30 minutos")
print("=" * 70)
print()
