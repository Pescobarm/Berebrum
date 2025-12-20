"""
ACTUALIZACIÓN: AUTO-CRAWLING
Ahora solo ingresa el dominio y el scanner crawlea automáticamente
"""

import shutil
import subprocess
import sys

print("=" * 70)
print("ACTUALIZACIÓN: AUTO-CRAWLING PARA COMMAND INJECTION TESTER")
print("=" * 70)
print()

# =====================================================
# PASO 1: INSTALAR BEAUTIFULSOUP4
# =====================================================
print("[1] Verificando dependencias...")

try:
    import bs4

    print("✅ BeautifulSoup4 ya instalado")
except ImportError:
    print("⚠️  BeautifulSoup4 no encontrado, instalando...")

    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "beautifulsoup4",
                "--break-system-packages",
            ]
        )
        print("✅ BeautifulSoup4 instalado")
    except:
        print("❌ Error al instalar BeautifulSoup4")
        print("   Instalar manualmente: pip install beautifulsoup4")
        print()
        input("Presiona Enter después de instalar...")

# =====================================================
# PASO 2: COPIAR WEB CRAWLER
# =====================================================
print("\n[2] Copiando Web Crawler...")

shutil.copy("web_crawler.py", "tools/web_crawler.py")
print("✅ tools/web_crawler.py")

# =====================================================
# PASO 3: ACTUALIZAR COMMAND INJECTION TESTER
# =====================================================
print("\n[3] Actualizando Command Injection Tester...")

# Backup
shutil.copy(
    "tools/command_injection_tester.py", "tools/command_injection_tester_v1_backup.py"
)
print("✅ Backup: tools/command_injection_tester_v1_backup.py")

# Reemplazar con v2
shutil.copy("command_injection_tester_v2.py", "tools/command_injection_tester.py")
print("✅ tools/command_injection_tester.py actualizado a v2.0")

# =====================================================
# PASO 4: ACTUALIZAR CLI
# =====================================================
print("\n[4] Actualizando CLI para mejor UX...")

# Backup
shutil.copy("cli/main.py", "cli/main_before_crawling.py")
print("✅ Backup: cli/main_before_crawling.py")

# Leer CLI
with open("cli/main.py", "r", encoding="utf-8") as f:
    cli_content = f.read()

# Cambiar mensaje de input
old_input = 'target = input("\\nTarget URL: ").strip()'
new_input = """target = input("\\nTarget (dominio o URL completa): ").strip()
    
    # Ejemplos:
    # - testphp.vulnweb.com (crawlea automáticamente)
    # - http://site.com/page.php?id=1 (prueba directamente)"""

if old_input in cli_content:
    cli_content = cli_content.replace(old_input, new_input)
    print("✅ Mensaje de input actualizado")
else:
    print("⚠️  Input ya actualizado o no encontrado")

# Guardar CLI
with open("cli/main.py", "w", encoding="utf-8") as f:
    f.write(cli_content)

print("✅ CLI actualizado")

# =====================================================
# PASO 5: LIMPIAR CACHÉ
# =====================================================
print("\n[5] Limpiando caché...")

try:
    shutil.rmtree("tools/__pycache__", ignore_errors=True)
    shutil.rmtree("cli/__pycache__", ignore_errors=True)
    print("✅ Caché limpiado")
except:
    pass

# =====================================================
# RESUMEN
# =====================================================
print("\n" + "=" * 70)
print("✅ ACTUALIZACIÓN COMPLETADA")
print("=" * 70)
print()
print("Cambios aplicados:")
print("  ✅ Web Crawler agregado (tools/web_crawler.py)")
print("  ✅ Command Injection Tester v2.0 con auto-crawling")
print("  ✅ CLI actualizado con mejor UX")
print("  ✅ BeautifulSoup4 instalado")
print()
print("=" * 70)
print("CÓMO FUNCIONA AHORA")
print("=" * 70)
print()
print("ANTES:")
print("  Input: http://testphp.vulnweb.com/listproducts.php?cat=1")
print("  → Prueba solo esa URL")
print()
print("AHORA:")
print("  Input: testphp.vulnweb.com")
print("  → Crawlea el sitio completo")
print("  → Encuentra todas las URLs con parámetros")
print("  → Prueba cada una automáticamente")
print("  → Reporta todas las vulnerabilidades")
print()
print("=" * 70)
print("PROBAR AHORA")
print("=" * 70)
print()
print("python -m cli.main")
print("→ OWASP Top 10")
print("→ 6. Command Injection Tester")
print()
print("Target: testphp.vulnweb.com")
print()
print("Verás:")
print("  [*] Modo: Auto-crawling")
print("  [*] Iniciando web crawler...")
print("  [*] Crawling [0]: http://testphp.vulnweb.com/...")
print("  [✓] Parámetros encontrados: cat")
print("  [✓] Parámetros encontrados: artist")
print("  [*] Encontradas 10 URLs con parámetros")
print("  [*] Escaneando cada una...")
print("  [1/10] http://testphp.vulnweb.com/listproducts.php?cat=...")
print("  [✓] No vulnerable")
print("  ...")
print()
print("✅ Ahora es mucho más fácil y automático!")
print()
