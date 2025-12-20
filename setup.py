#!/usr/bin/env python3
"""Berebrum - Setup Script"""

import sys
from pathlib import Path

print("=" * 60)
print("  Berebrum - Inicializacion")
print("=" * 60)
print("")

# Verificar Python 3.14+
if sys.version_info < (3, 14):
    print("ADVERTENCIA: Se recomienda Python 3.14 o superior")
    print(f"Tu version: Python {sys.version_info.major}.{sys.version_info.minor}")

    # Permitir Python 3.12+ pero con advertencia
    if sys.version_info < (3, 12):
        print("")
        print("ERROR: Python 3.12 es el minimo requerido")
        print("Descarga Python 3.13 desde: https://www.python.org/downloads/")
        sys.exit(1)

    print("Continuando con Python 3.12 (funcional pero no optimo)...")
    print("")

print(
    f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
)

# Crear directorios
directories = ["database", "data", "logs"]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)
print("✓ Directorios creados")

# Inicializar base de datos
try:
    from core.database import db_manager

    db_manager.init_db()
except Exception as e:
    print(f"ERROR: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)

print("")
print("=" * 60)
print("✅ Setup completado!")
print("=" * 60)
print("")
print("Proximos pasos:")
print("  python cli/main.py")
print("")
