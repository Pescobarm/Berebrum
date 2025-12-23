import requests
import json
import os
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder


class MobSFCommander:
    def __init__(self, host="127.0.0.1", port=8000):
        # La API Key de MobSF es fija por defecto o se puede configurar.
        # En entornos locales dockerizados suele ser accesible sin auth compleja,
        # pero para usar la API necesitamos la key que MobSF genera al inicio.
        # NOTA: Para simplificar, asumiremos que el usuario pondrá la API Key en el .env
        # después del primer inicio, o podemos intentar hacer scraping (más complejo).

        self.server = f"http://{host}:{port}"
        self.api_key = os.getenv("MOBSF_API_KEY", "")

    def is_alive(self):
        try:
            r = requests.get(self.server, timeout=5)
            return r.status_code == 200
        except:
            return False

    def upload_and_scan(self, file_path):
        """Sube un APK/IPA y lanza el escaneo estático"""
        if not self.api_key:
            return {
                "error": "Falta MOBSF_API_KEY en .env. Inicia MobSF, copia la API Key de la web (http://localhost:8000/api_docs) y ponla en tu .env"
            }

        if not os.path.exists(file_path):
            return {"error": f"Archivo no encontrado: {file_path}"}

        print(f"    📤 Subiendo archivo: {os.path.basename(file_path)}...")

        # Endpoint de subida
        url = f"{self.server}/api/v1/upload"

        multipart_data = MultipartEncoder(
            fields={
                "file": (
                    os.path.basename(file_path),
                    open(file_path, "rb"),
                    "application/octet-stream",
                )
            }
        )

        headers = {
            "Content-Type": multipart_data.content_type,
            "Authorization": self.api_key,
        }

        try:
            response = requests.post(url, data=multipart_data, headers=headers)
            if response.status_code == 200:
                data = response.json()
                scan_type = data.get("scan_type")
                file_name = data.get("file_name")
                hash_md5 = data.get("hash")

                print(f"    ✅ Archivo recibido. Iniciando escaneo ({scan_type})...")
                return self._trigger_scan(hash_md5, scan_type, file_name)
            else:
                return {"error": f"Error subida: {response.text}"}
        except Exception as e:
            return {"error": str(e)}

    def _trigger_scan(self, file_hash, scan_type, file_name):
        """Dispara el análisis"""
        url = f"{self.server}/api/v1/scan"
        headers = {"Authorization": self.api_key}
        data = {
            "hash": file_hash,
            "scan_type": scan_type,
            "file_name": file_name,
            "re_scan": 0,
        }

        print("    ⏳ Analizando (esto puede tardar 1-2 minutos)...")
        r = requests.post(url, data=data, headers=headers)

        if r.status_code == 200:
            print("    ✅ Análisis completado.")
            return r.json()  # Retorna el reporte completo
        else:
            return {"error": f"Fallo en escaneo: {r.status_code}"}

    def generate_pdf(self, file_hash):
        """Genera reporte PDF"""
        url = f"{self.server}/api/v1/download_pdf"
        headers = {"Authorization": self.api_key}
        data = {"hash": file_hash}

        r = requests.post(url, data=data, headers=headers, stream=True)
        if r.status_code == 200:
            return r.content
        return None
