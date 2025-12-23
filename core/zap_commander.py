import time
import os
from zapv2 import ZAPv2  # <--- IMPORT CORRECTO (Mayúsculas)
from dotenv import load_dotenv

load_dotenv()


class ZapCommander:
    def __init__(self):
        # Configuración desde .env
        self.api_key = os.getenv("ZAP_API_KEY")
        self.host = os.getenv("ZAP_HOST", "127.0.0.1")
        self.port = os.getenv("ZAP_PORT", "8090")

        # Construimos la URL del Proxy
        self.proxy_url = f"http://{self.host}:{self.port}"
        self.zap = None

    def connect(self):
        """Establece conexión con la API de ZAP"""
        try:
            print(f"    🔌 Conectando a ZAP en {self.proxy_url}...")

            # --- CORRECCIÓN AQUÍ: Usamos ZAPv2 (Mayúsculas) ---
            self.zap = ZAPv2(
                apikey=self.api_key,
                proxies={"http": self.proxy_url, "https": self.proxy_url},
            )

            # Verificamos si responde consultando la versión
            version = self.zap.core.version
            print(f"    ✅ Conexión establecida. ZAP Versión: {version}")
            return True
        except Exception as e:
            print(f"    ❌ Error conectando a ZAP: {e}")
            print(
                "       Asegúrate de que el contenedor 'berebrum-zap' esté corriendo."
            )
            return False

    def start_spider(self, target_url):
        """Lanza la araña (Crawler) para descubrir mapas del sitio"""
        if not self.zap:
            self.connect()

        print(f"    🕷️ Lanzando Spider contra: {target_url}")
        scan_id = self.zap.spider.scan(target_url)

        # Esperamos a que termine
        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"       Progreso Spider: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)

        print("    ✅ Spider finalizado. Sitio mapeado.")
        return True

    def start_active_scan(self, target_url):
        """Lanza el ataque real (Active Scan)"""
        if not self.zap:
            self.connect()

        print(f"    ⚔️ Iniciando Escaneo Activo (Ataque) contra: {target_url}")
        print("       (Esto puede tardar varios minutos...)")

        scan_id = self.zap.ascan.scan(target_url)

        while int(self.zap.ascan.status(scan_id)) < 100:
            print(f"       Progreso Ataque: {self.zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("    ✅ Escaneo Activo finalizado.")
        return True

    def get_alerts(self, target_url):
        """Obtiene los hallazgos de seguridad"""
        if not self.zap:
            self.connect()

        # Filtramos alertas por riesgo
        alerts = self.zap.core.alerts(baseurl=target_url)
        return alerts
