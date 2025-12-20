"""
Instalador de SSTImap para Berebrum
SSTImap es un fork actualizado de tplmap (Python 3 compatible)
"""

import os
import subprocess
import sys

def install_sstimap():
    print("="*70)
    print("INSTALADOR DE SSTIMAP PARA BEREBRUM")
    print("SSTImap = Fork actualizado de tplmap (Python 3)")
    print("="*70)
    
    install_dir = os.path.join(os.getcwd(), "sstimap")
    
    print(f"\n[*] Directorio de instalación: {install_dir}")
    
    # Check git
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        print("[✓] Git encontrado")
    except:
        print("[!] ERROR: Git no está instalado")
        return False
    
    # Clone SSTImap
    if os.path.exists(install_dir):
        print(f"[!] El directorio {install_dir} ya existe")
        overwrite = input("    ¿Sobrescribir? [y/N]: ").lower()
        if overwrite == 'y':
            import shutil
            shutil.rmtree(install_dir)
        else:
            print("[*] Usando instalación existente")
            return True
    
    print(f"\n[*] Clonando SSTImap desde GitHub...")
    try:
        result = subprocess.run(
            ["git", "clone", "https://github.com/vladko312/SSTImap.git", install_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print("[✓] SSTImap clonado exitosamente")
        else:
            print(f"[!] Error al clonar: {result.stderr}")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    
    # Install requirements
    print(f"\n[*] Instalando dependencias de SSTImap...")
    requirements_file = os.path.join(install_dir, "requirements.txt")
    
    if os.path.exists(requirements_file):
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", requirements_file],
                check=True
            )
            print("[✓] Dependencias instaladas")
        except Exception as e:
            print(f"[!] Error instalando dependencias: {e}")
            return False
    else:
        print("[!] Archivo requirements.txt no encontrado")
    
    # Test installation
    print(f"\n[*] Probando instalación...")
    sstimap_path = os.path.join(install_dir, "sstimap.py")
    
    if os.path.exists(sstimap_path):
        try:
            result = subprocess.run(
                [sys.executable, sstimap_path, "-h"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if "sstimap" in result.stdout.lower() or "usage" in result.stdout.lower():
                print("[✓] SSTImap instalado correctamente")
                print(f"\n{'='*70}")
                print("✅ INSTALACIÓN COMPLETADA")
                print("="*70)
                print(f"\nRuta de SSTImap: {sstimap_path}")
                print(f"\nVentajas de SSTImap:")
                print(f"  ✅ Compatible con Python 3")
                print(f"  ✅ Fork actualizado de tplmap")
                print(f"  ✅ Más engines soportados")
                print(f"  ✅ Mejor detección de WAF bypass")
                
                print(f"\nUso manual:")
                print(f"  cd sstimap")
                print(f"  python sstimap.py -u 'http://target.com?param=*'")
                
                return True
            else:
                print("[!] SSTImap no responde correctamente")
                return False
        except Exception as e:
            print(f"[!] Error probando SSTImap: {e}")
            return False
    else:
        print(f"[!] No se encontró sstimap.py en {sstimap_path}")
        return False


if __name__ == "__main__":
    print("\n")
    success = install_sstimap()
    
    if success:
        print("\n✅ SSTImap instalado exitosamente")
        print("\n[*] Uso recomendado:")
        print("    cd sstimap")
        print("    python sstimap.py -u 'http://somosandina.ar?name=*'")
        print("\n[*] Para integrar con Berebrum:")
        print("    Actualizar ssti_detector.py para soportar sstimap")
    else:
        print("\n[!] Instalación fallida")
    
    input("\nPresiona Enter para salir...")