import time
from core.msf_commander import MsfCommander


def simulacro_ataque():
    print("\n🧪 --- INICIANDO SIMULACRO DE LABORATORIO --- 🧪")
    print("Objetivo: Validar conexión Python -> Metasploit y creación de Jobs.")

    # 1. Definimos un objetivo ficticio (Tu propio localhost)
    # No te preocupes, el ataque fallará porque no tienes el puerto abierto,
    # pero lo que nos importa es que Metasploit reciba la orden y cree el JOB.
    target_fake = "127.0.0.1"

    # 2. Simulamos que Nmap encontró esto:
    print(f"\n[SIMULACIÓN] Nmap reporta: 'vsftpd 2.3.4' en {target_fake}:21")

    # 3. Iniciamos el Comandante
    commander = MsfCommander(password="berebrum_secret")

    print("🔵 Conectando con la base (Docker Metasploit)...")
    if commander.connect():
        print("✅ Conexión establecida.")

        # 4. ORDENAMOS EL ATAQUE
        # Le decimos manualmente: "Ataca esto como si fueras main.py"
        print(f"\n⚡ Enviando orden de ataque al puerto 21...")
        resultado = commander.auto_exploit(target_fake, "vsftpd 2.3.4", 21)

        if resultado:
            print("\n🎉 ¡ÉXITO! La orden fue recibida y procesada.")
            print("Esto confirma que:")
            print("   1. Python se autenticó correctamente.")
            print("   2. Encontró el exploit en attack_mapping.py.")
            print("   3. Metasploit generó un Job ID.")
        else:
            print("\n❌ FALLO: El comandante no pudo disparar.")

    else:
        print("\n❌ ERROR CRÍTICO: No se puede conectar al puerto 55553.")
        print("Asegúrate de haber hecho 'docker-compose up'")


if __name__ == "__main__":
    simulacro_ataque()
