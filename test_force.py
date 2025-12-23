from pymetasploit3.msfrpc import MsfRpcClient
import os
import time


def check_connection():
    host = os.getenv("MSF_HOST", "berebrum-force")
    password = os.getenv("MSF_PASSWORD", "berebrum_secret")

    print(f"\n📡 Intentando conectar a la Fuerza en: {host}:55553 ...")

    try:
        # Intentamos conectar al cliente RPC
        client = MsfRpcClient(password, port=55553, server=host, ssl=False)

        # Si pasa, pedimos la versión para confirmar
        version = client.call("core.version")
        print(f"✅ ¡CONEXIÓN EXITOSA!")
        print(f"🔩 Versión de Metasploit: {version.get('version')}")
        print(f"ruby: {version.get('ruby')}")
        print("🚀 El Cerebro y la Fuerza están sincronizados.")

    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        print(
            "💡 Tip: Asegúrate que el contenedor 'berebrum_force_unit' terminó de cargar (tarda unos segundos)."
        )


if __name__ == "__main__":
    check_connection()
