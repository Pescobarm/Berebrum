import os
import requests
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()


def prueba_blindaje_movil():
    print("\n📱 --- TEST DE CONEXIÓN MOBILE FORTRESS (MobSF) ---")

    # 1. Obtener Configuración
    api_key = os.getenv("MOBSF_API_KEY")
    host = "127.0.0.1"
    port = "8000"
    base_url = f"http://{host}:{port}"

    print(f"    🔑 Verificando API Key: {'Presente' if api_key else '❌ AUSENTE'}")
    if not api_key:
        print("       Error: Debes poner la MOBSF_API_KEY en tu archivo .env")
        return

    # 2. Verificar si el servicio responde (Ping básico)
    try:
        r = requests.get(base_url, timeout=5)
        if r.status_code == 200:
            print("    ✅ Servicio MobSF detectado y corriendo.")
        else:
            print(f"    ⚠️ El servicio responde con código inusual: {r.status_code}")
    except requests.exceptions.ConnectionError:
        print("    ❌ ERROR CRÍTICO: No se puede conectar a localhost:8000")
        print("       Asegúrate de que el contenedor Docker esté encendido.")
        return

    # 3. Verificar Autenticación (Prueba real)
    # Intentamos leer la lista de escaneos previos. Esto requiere una API Key válida.
    print("    🔐 Validando credenciales de acceso...")
    try:
        headers = {"Authorization": api_key}
        # Endpoint para listar escaneos recientes
        r = requests.get(f"{base_url}/api/v1/scans", headers=headers)

        if r.status_code == 200:
            print("\n    🎉 ¡ÉXITO! Autorización confirmada.")
            print("       Berebrum tiene control total sobre el módulo móvil.")
            print(
                f"       Respuesta de la API: {r.json().get('scans', [])[:1]}"
            )  # Muestra un fragmento si hay datos
        elif r.status_code == 401 or r.status_code == 403:
            print("\n    ❌ FALLO DE AUTORIZACIÓN.")
            print("       Tu servidor MobSF está vivo, pero rechazó tu llave.")
            print(
                "       Verifica que la API Key en .env sea EXACTAMENTE la que muestra http://localhost:8000/api_docs"
            )
        else:
            print(f"\n    ❌ Error inesperado: {r.status_code} - {r.text}")

    except Exception as e:
        print(f"    ❌ Excepción: {e}")


if __name__ == "__main__":
    prueba_blindaje_movil()
