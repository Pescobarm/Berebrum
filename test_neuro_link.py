import sys
import os
import time
from dotenv import load_dotenv

# Cargar entorno para leer MSF_PASSWORD
load_dotenv()

# Aseguramos que Python encuentre los módulos
sys.path.append(os.getcwd())


def print_step(msg):
    print(f"\n🔹 {msg}")


def test_neuro_link_system():
    print("\n🧠 --- TEST DE SISTEMA: NEURO-LINK (Metasploit Bridge) --- 🧠")

    # --- VERIFICACIÓN DE ARCHIVOS ---
    try:
        from core.msf.commander import MsfCommander
        from core.msf.mapping import get_exploit_config

        print("✅ Archivos del Core encontrados correctamente.")
    except ImportError as e:
        print(f"❌ ERROR CRÍTICO: No se encuentran los módulos nuevos.")
        print(f"   Detalle: {e}")
        print(
            "   Asegúrate de haber creado la carpeta 'core/msf/' con 'commander.py' y 'mapping.py'."
        )
        sys.exit(1)

    # --- PASO 1: VERIFICAR INTELIGENCIA (MAPPING) ---
    print_step("PASO 1: Verificando 'Cerebro' (Matriz de Ataque)...")

    # Simulamos un hallazgo de Nmap: vsftpd versión 2.3.4 (Vulnerable clásica)
    test_service = "vsftpd"
    test_version = "2.3.4"

    print(f"   🔎 Consultando base de datos para: {test_service} ({test_version})")
    config = get_exploit_config(test_service, test_version)

    if config:
        print(f"   ✅ MATCH CONFIRMADO:")
        print(f"      - Módulo:  {config['module']}")
        print(f"      - CVSS:    {config['cvss_score']} ({config['severity']})")
        print(f"      - Payload: {config['payload_compatible'][0]}")
    else:
        print(
            "   ❌ FALLO: El mapping no encontró el exploit conocido. Revisa core/msf/mapping.py"
        )
        return

    # --- PASO 2: CONEXIÓN CON EL MÚSCULO (RPC) ---
    print_step("PASO 2: Conectando con 'Fuerza' (Docker Metasploit RPC)...")

    password = os.getenv("MSF_PASSWORD")
    if not password:
        print(
            "   ⚠️ ADVERTENCIA: No se detectó MSF_PASSWORD en .env. Usando default 'berebrum'."
        )

    # Instanciamos el nuevo Commander (versión RPC)
    try:
        commander = MsfCommander()
    except Exception as e:
        print(f"   ❌ Error al instanciar MsfCommander: {e}")
        return

    if commander.connect():
        # Intentamos obtener la versión para confirmar tráfico bidireccional
        try:
            version_info = commander.get_version()
            ver_str = version_info.get("version", "Desconocida")
            ruby_ver = version_info.get("ruby", "Desconocida")
            print(f"   ✅ CONEXIÓN ESTABLECIDA EXITOSAMENTE.")
            print(f"      - Metasploit Version: {ver_str}")
            print(f"      - Ruby Version:       {ruby_ver}")
            print(f"      - Consola Virtual ID: {commander.cid}")
        except Exception as e:
            print(f"   ⚠️ Conectó, pero falló al pedir versión: {e}")
    else:
        print(
            "   ❌ FALLO DE CONEXIÓN: No se pudo hablar con el contenedor 'berebrum-force'."
        )
        print("      Diagnóstico:")
        print("      1. ¿Está corriendo el contenedor? (docker ps)")
        print("      2. ¿El puerto 55553 está expuesto? (Ver docker-compose.yml)")
        print("      3. ¿La contraseña en .env coincide con la del contenedor?")
        return

    # --- PASO 3: SIMULACRO DE DISPARO ---
    print_step("PASO 3: Simulacro de Fuego (Auto-Exploit)...")

    target_simulado = "127.0.0.1"  # IP segura (Loopback)
    port_simulado = 21
    print(f"   🎯 Objetivo Simulado: {target_simulado}:{port_simulado}")
    print("   ⚡ Enviando secuencia de ataque...")

    # Esto invocará la función auto_exploit del commander
    # No explotará nada real, pero enviará los comandos a la consola remota
    try:
        commander.auto_exploit(target_simulado, test_service, port_simulado)

        print("\n   ✅ ORDEN ENVIADA CORRECTAMENTE.")
        print(
            "      Si viste los logs de 'Configurando exploit...', el Neuro-Link funciona."
        )
        print("      Tu sistema está listo para integrarse al Main.")
    except Exception as e:
        print(f"   ❌ ERROR DURANTE LA EJECUCIÓN DEL ATAQUE: {e}")

    print("\n🏁 FIN DEL TEST.")


if __name__ == "__main__":
    test_neuro_link_system()
