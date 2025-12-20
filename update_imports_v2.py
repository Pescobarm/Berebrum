"""
ACTUALIZACIÓN AUTOMÁTICA DE IMPORTS v2.0
Después de ejecutar migrate_structure.py
"""

import os
import re
import shutil

print("=" * 70)
print("ACTUALIZACIÓN AUTOMÁTICA DE IMPORTS V2.0")
print("=" * 70)
print()

# Mapeo de cambios de imports
IMPORT_MAPPING = {
    # Reconnaissance
    r"from tools\.subdomain_enumerator import": "from tools.reconnaissance.subdomain_enumerator import",
    r"from tools\.port_scanner import": "from tools.reconnaissance.port_scanner import",
    r"from tools\.web_directory_scanner import": "from tools.reconnaissance.web_directory_scanner import",
    r"from tools\.dns_enum import": "from tools.reconnaissance.dns_enum import",
    r"from tools\.whois_lookup import": "from tools.reconnaissance.whois_lookup import",
    r"from tools\.ssl_scanner import": "from tools.reconnaissance.ssl_scanner import",
    # OWASP Top 10
    r"from tools\.sql_injection_scanner import": "from tools.owasp_top10.sql_injection_scanner import",
    r"from tools\.xss_detector import": "from tools.owasp_top10.xss_detector import",
    r"from tools\.csrf_tester import": "from tools.owasp_top10.csrf_tester import",
    r"from tools\.lfi_rfi_scanner import": "from tools.owasp_top10.lfi_rfi_scanner import",
    r"from tools\.command_injection_tester import": "from tools.owasp_top10.command_injection_tester import",
    # Brute Force
    r"from tools\.ssh_brute_force import": "from tools.brute_force.ssh_brute_force import",
    r"from tools\.ftp_brute_force import": "from tools.brute_force.ftp_brute_force import",
}


def update_imports_in_file(filepath):
    """Actualiza imports en un archivo"""

    if not os.path.exists(filepath):
        print(f"⚠️  {filepath} no existe, saltando...")
        return False

    print(f"\n[*] Procesando: {filepath}")

    # Backup
    backup_path = f"{filepath}.backup"
    shutil.copy(filepath, backup_path)
    print(f"    ✅ Backup: {backup_path}")

    # Leer
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original_content = content
    changes = []

    # Aplicar cambios
    for old_pattern, new_import in IMPORT_MAPPING.items():
        matches = re.findall(old_pattern, content)
        if matches:
            content = re.sub(old_pattern, new_import, content)
            changes.append(f"{old_pattern} → {new_import}")

    # Guardar si hubo cambios
    if content != original_content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"    ✅ {len(changes)} imports actualizados:")
        for change in changes[:5]:  # Mostrar primeros 5
            print(f"       • {change}")
        if len(changes) > 5:
            print(f"       ... y {len(changes) - 5} más")

        return True
    else:
        print(f"    ℹ️  Sin cambios necesarios")
        return False


# Archivos a actualizar
files_to_update = [
    "cli/main.py",
    "dashboard/app.py",
    "core/ai_operator.py",
    "core/mcp_orchestrator.py",
]

print("[1] Actualizando imports en archivos principales...")
print()

updated_files = []
for filepath in files_to_update:
    if update_imports_in_file(filepath):
        updated_files.append(filepath)

print("\n" + "=" * 70)
print("RESUMEN")
print("=" * 70)
print()

if updated_files:
    print(f"✅ {len(updated_files)} archivos actualizados:")
    for f in updated_files:
        print(f"   • {f}")
else:
    print("ℹ️  No se requirieron actualizaciones")

print()
print("=" * 70)
print("VERIFICACIÓN DE SINTAXIS")
print("=" * 70)
print()

# Verificar sintaxis
print("[2] Verificando sintaxis de archivos actualizados...")
print()

all_valid = True
for filepath in files_to_update:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            compile(content, filepath, "exec")
            print(f"✅ {filepath} - Sintaxis correcta")
        except SyntaxError as e:
            print(f"❌ {filepath} - Error de sintaxis: {e}")
            all_valid = False

            # Restaurar backup
            backup_path = f"{filepath}.backup"
            if os.path.exists(backup_path):
                shutil.copy(backup_path, filepath)
                print(f"   ⚠️  Restaurado desde backup")

print()
print("=" * 70)
print("LIMPIEZA")
print("=" * 70)
print()

# Limpiar backups si todo está bien
if all_valid:
    print("[3] Limpiando archivos de backup...")
    for filepath in files_to_update:
        backup_path = f"{filepath}.backup"
        if os.path.exists(backup_path):
            os.remove(backup_path)
            print(f"✅ Eliminado: {backup_path}")

    # Limpiar cache
    print("\n[4] Limpiando caché de Python...")
    try:
        shutil.rmtree("cli/__pycache__", ignore_errors=True)
        shutil.rmtree("dashboard/__pycache__", ignore_errors=True)
        shutil.rmtree("core/__pycache__", ignore_errors=True)
        shutil.rmtree("tools/__pycache__", ignore_errors=True)
        print("✅ Caché limpiado")
    except:
        pass
else:
    print("⚠️  Hay errores de sintaxis, backups preservados")

print()
print("=" * 70)
print("✅ ACTUALIZACIÓN DE IMPORTS COMPLETADA")
print("=" * 70)
print()

if all_valid:
    print("Próximo paso:")
    print("  1. Verificar CLI:       python -m cli.main")
    print("  2. Verificar Dashboard: streamlit run dashboard/app.py")
    print("  3. Si todo funciona:    git add . && git commit")
else:
    print("⚠️  Revisa los errores antes de continuar")

print()
