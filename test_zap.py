from core.zap_commander import ZapCommander


def prueba_zap():
    print("\n--- TEST DE CONEXIÓN WEB HUNTER ---")

    # 1. Instanciar
    commander = ZapCommander()

    # 2. Conectar
    if commander.connect():
        print("\n🎉 ¡ÉXITO! Berebrum tiene control total sobre ZAP.")
        print("El sistema está listo para auditorías web automatizadas.")
    else:
        print("\n❌ FALLO. Revisa que:")
        print("   1. 'docker ps' muestre berebrum-zap corriendo.")
        print("   2. Tu archivo .env tenga la ZAP_API_KEY correcta.")
        print("   3. Hayas instalado 'pip install python-owasp-zap-v2.4'")


if __name__ == "__main__":
    prueba_zap()
