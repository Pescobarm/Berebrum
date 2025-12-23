import os
import subprocess
import sys

# -------------------------------------------------------------------------
# ⚙️ CONFIGURACIÓN DE FILTROS
# -------------------------------------------------------------------------

# Carpetas que el buscador manual (Python) IGNORARÁ por completo
EXCLUDE_DIRS_NAMES = {
    "venv",
    ".git",
    "__pycache__",
    ".idea",
    ".vscode",
    "site-packages",
}

# Rutas específicas relativas a ignorar (útil para rutas anidadas como data/wordlists)
EXCLUDE_PATHS_PARTIAL = [
    os.path.join("data", "wordlists"),
    os.path.join("venv"),
]

# Extensiones de archivo que SÍ queremos auditar
TARGET_EXTENSIONS = {".py", ".yml", ".yaml", ".txt", ".md", ".env.example"}

# Palabras clave que levantan sospechas
KEYWORDS = ["password", "secret", "api_key", "token", "access_key"]

# -------------------------------------------------------------------------
# 🛠️ FUNCIONES
# -------------------------------------------------------------------------


def run_command(command, description):
    """Ejecuta una herramienta de CLI y formatea la salida"""
    print(f"\n{'='*70}")
    print(f"🕵️  EJECUTANDO: {description}")
    print(f"{'='*70}")
    try:
        # nosec: subprocess es necesario para orquestar herramientas de seguridad
        result = subprocess.run(
            command, shell=True, text=True, capture_output=True
        )  # nosec

        # Imprimimos stdout si hay algo relevante
        if result.stdout:
            print(result.stdout)

        # Filtramos errores técnicos que no son vulnerabilidades
        if result.stderr:
            errors = [
                line
                for line in result.stderr.split("\n")
                if line.strip() and "WARNING" not in line
            ]
            if errors:
                print("⚠️  NOTAS DEL SISTEMA:")
                for err in errors:
                    print(f"   {err}")

        if result.returncode == 0:
            print(f"✅  {description}: FINALIZADO CORRECTAMENTE")
        else:
            # Bandit retorna exit code 1 si encuentra problemas, lo cual es 'bueno' para nosotros saberlo
            print(f"⚠️  {description}: REPORTE GENERADO (Revisar arriba)")

    except Exception as e:
        print(f"❌ Error crítico ejecutando {description}: {e}")


def is_path_excluded(root_path):
    """Verifica si la ruta actual debe ser ignorada"""
    # Normalizar ruta para el sistema operativo actual
    norm_root = os.path.normpath(root_path)

    for excluded in EXCLUDE_PATHS_PARTIAL:
        if excluded in norm_root:
            return True
    return False


def search_secrets_pythonic():
    """Busca secretos en el código, evitando falsos positivos de librerías y wordlists"""
    print(f"\n{'='*70}")
    print(f"🕵️  EJECUTANDO: Búsqueda de Secretos (Motor Python Personalizado)")
    print(f"{'='*70}")
    print(f"ℹ️  Ignorando rutas: {', '.join(EXCLUDE_PATHS_PARTIAL)}")

    issues_found = False
    files_scanned = 0

    for root, dirs, files in os.walk("."):
        # 1. Modificar 'dirs' in-place para no entrar en carpetas prohibidas (venv, .git)
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS_NAMES]

        # 2. Chequeo extra de ruta completa (para atrapar data/wordlists)
        if is_path_excluded(root):
            continue

        for file in files:
            # 3. Solo revisar extensiones de código/config
            if not any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                continue

            # 4. Ignorar este script y el archivo .env real (que sabemos que tiene secretos)
            if file in ["audit_code.py", ".env"]:
                continue

            files_scanned += 1
            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        line_stripped = line.strip()
                        line_lower = line_stripped.lower()

                        # Si encontramos una palabra clave...
                        if any(k in line_lower for k in KEYWORDS):

                            # --- FILTROS DE FALSOS POSITIVOS ---
                            # Ignorar si es una lectura de variable de entorno
                            if "os.getenv" in line or "os.environ" in line:
                                continue
                            # Ignorar inputs de usuario ("Ingrese su password")
                            if "input(" in line or "print(" in line:
                                continue
                            # Ignorar definiciones de funciones o clases
                            if "def " in line or "class " in line:
                                continue
                            # Ignorar si parece un comentario (a veces es TODO: remove password)
                            if line_stripped.startswith("#"):
                                # Aún así, alertamos si el comentario dice explícitamente la clave
                                if "=" not in line_stripped:
                                    continue
                                # Ignorar si es una referencia a variable de entorno tipo ${VAR}
                                if "${" in line and "}" in line:
                                    continue
                                # --------------------

                            # Si pasa los filtros, es sospechoso
                            print(f"🚩 Posible secreto en: {file_path}:{i}")
                            print(f"   >> {line_stripped[:100]}...")
                            issues_found = True

            except Exception:
                pass  # Archivos binarios o bloqueados

    print(f"\n📊 Archivos escaneados: {files_scanned}")
    if not issues_found:
        print("✅  No se encontraron secretos hardcodeados evidentes.")
    else:
        print("❌  Se detectaron posibles secretos (Revisar lista arriba).")


def main():
    print("\n🛡️  INICIANDO PROTOCOLO DE AUDITORÍA BEREBRUM V3.0 🛡️")
    print("   Target: Directorio Actual")
    print("   Excluyendo: venv, .git, data/wordlists")

    # 1. BANDIT
    # -r: recursivo
    # -x: excluir rutas (separadas por coma). Agregamos data/wordlists aquí
    # -ll: nivel de reporte (medium/high)
    bandit_exclusions = "./venv,./.git,./data/wordlists"
    run_command(f"bandit -r . -x {bandit_exclusions} -ll", "BANDIT (Análisis Estático)")

    # 2. SAFETY (Solo revisa dependencias instaladas, no archivos locales)
    run_command("safety scan", "SAFETY (Dependencias Vulnerables)")

    # 3. BÚSQUEDA MANUAL FILTRADA
    search_secrets_pythonic()


if __name__ == "__main__":
    main()
