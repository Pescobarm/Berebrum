"""
DIAGNÓSTICO DEFINITIVO:
Encontrar TODOS los lugares que guardan logs
"""

import os

print("="*70)
print("DIAGNÓSTICO: ENCONTRAR TODOS LOS LOGS")
print("="*70)
print()

locations_found = []

# ===== 1. CLI/MAIN.PY =====
print("[1] Analizando cli/main.py...")

if os.path.exists("cli/main.py"):
    with open("cli/main.py", "r", encoding="utf-8") as f:
        cli_content = f.read()
        cli_lines = cli_content.split('\n')
    
    # Buscar TODAS las llamadas a create_log
    for i, line in enumerate(cli_lines):
        if 'db_manager.create_log' in line or 'create_log(' in line:
            locations_found.append({
                'file': 'cli/main.py',
                'line': i+1,
                'code': line.strip()[:80]
            })
    
    print(f"✅ Encontradas {len([l for l in locations_found if l['file'] == 'cli/main.py'])} llamadas")
    
    for loc in locations_found:
        if loc['file'] == 'cli/main.py':
            print(f"   Línea {loc['line']}: {loc['code']}")

else:
    print("❌ cli/main.py no encontrado")

# ===== 2. TOOLS/EXECUTOR.PY =====
print("\n[2] Analizando tools/executor.py...")

if os.path.exists("tools/executor.py"):
    with open("tools/executor.py", "r", encoding="utf-8") as f:
        exec_content = f.read()
        exec_lines = exec_content.split('\n')
    
    exec_logs = []
    for i, line in enumerate(exec_lines):
        if 'db_manager.create_log' in line or 'create_log(' in line:
            exec_logs.append({
                'file': 'tools/executor.py',
                'line': i+1,
                'code': line.strip()[:80]
            })
            locations_found.append(exec_logs[-1])
    
    if exec_logs:
        print(f"⚠️  Encontradas {len(exec_logs)} llamadas")
        for loc in exec_logs:
            print(f"   Línea {loc['line']}: {loc['code']}")
    else:
        print("✅ No hay llamadas a create_log")

else:
    print("ℹ️  tools/executor.py no encontrado")

# ===== 3. BUSCAR EN TODO EL PROYECTO =====
print("\n[3] Buscando en todo el proyecto...")

all_files = []
for root, dirs, files in os.walk('.'):
    # Ignorar directorios
    dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'venv', 'env']]
    
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            all_files.append(filepath)

other_logs = []
for filepath in all_files:
    if 'cli/main.py' in filepath or 'tools/executor.py' in filepath:
        continue
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        
        if 'db_manager.create_log' in content or 'create_log(' in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'db_manager.create_log' in line or 'create_log(' in line:
                    other_logs.append({
                        'file': filepath,
                        'line': i+1,
                        'code': line.strip()[:80]
                    })
    except:
        pass

if other_logs:
    print(f"⚠️  Encontradas {len(other_logs)} llamadas en otros archivos:")
    for loc in other_logs[:10]:
        print(f"   {loc['file']}:{loc['line']}")
        print(f"      {loc['code']}")
else:
    print("✅ No hay llamadas en otros archivos")

# ===== RESUMEN =====
print("\n" + "="*70)
print("RESUMEN")
print("="*70)
print()

total = len(locations_found) + len(other_logs)
print(f"Total de llamadas a create_log: {total}")
print()

if total == 0:
    print("✅ No se encontraron llamadas (extraño)")
elif total == 1:
    print("✅ Solo 1 llamada (correcto)")
    print("\nPero siguen apareciendo 3 logs...")
    print("Posibilidades:")
    print("  1. Hay un wrapper que llama la función 3 veces")
    print("  2. Hay un try/except/finally que guarda múltiples veces")
    print("  3. Hay código en un lugar inesperado")
else:
    print(f"⚠️  {total} llamadas encontradas")
    print("\nUbicaciones:")
    
    # Agrupar por archivo
    by_file = {}
    for loc in locations_found + other_logs:
        file = loc['file']
        if file not in by_file:
            by_file[file] = []
        by_file[file].append(loc)
    
    for file, locs in by_file.items():
        print(f"\n{file}: {len(locs)} llamadas")
        for loc in locs:
            print(f"  Línea {loc['line']}: {loc['code']}")

print("\n" + "="*70)
print("SIGUIENTE PASO")
print("="*70)
print()
print("Si hay múltiples llamadas:")
print("  → Eliminar todas excepto la de run_lfi_rfi_scanner")
print()
print("Si solo hay 1 llamada:")
print("  → Buscar wrappers que llamen la función múltiples veces")
print("  → Revisar try/except/finally")
print()