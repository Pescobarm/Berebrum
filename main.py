import sys
import os
import subprocess
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()  # Esto carga las variables del archivo .env al sistema

# Database
from database.session import engine, SessionLocal
from database.models import Base, Project, AttackFlow, Finding
from core.safety import ScopeGuardian

# --- DASHBOARD IMPORT ---
from core.dashboard import view_attack_flow, save_attack_flow

# Tools Imports
from mcp_servers.reconnaissance.nmap_scanner import NmapScanner
from mcp_servers.reconnaissance.dir_scanner import DirScanner
from mcp_servers.reconnaissance.subdomain_enum import SubdomainEnum
from mcp_servers.network.banner_grabber import BannerGrabber
from mcp_servers.network.ssh_cracker import SSHCracker
from mcp_servers.web_owasp.lfi_scanner import LFIScanner
from mcp_servers.web_owasp.header_analyzer import HeaderAnalyzer
from mcp_servers.web_owasp.sqli_scanner import SQLiScanner
from mcp_servers.web_owasp.xss_scanner import XSSScanner
from mcp_servers.web_owasp.ssti_scanner import SSTIScanner
from mcp_servers.reporting.html_generator import HtmlReporter
from mcp_servers.reconnaissance.param_miner import ParamMiner
from mcp_servers.reconnaissance.waf_detector import WafDetector
from mcp_servers.reconnaissance.cms_scanner import CMSScanner
from mcp_servers.network.arp_spoofer import ArpSpoofer
from mcp_servers.web_owasp.secret_hunter import SecretHunter
from mcp_servers.web_owasp.ssl_validator import SSLValidator

# --- COMMANDERS ---
from core.msf.commander import MsfCommander
from core.zap_commander import ZapCommander
from core.mobsf_commander import MobSFCommander  # <--- INTEGRACIÓN MÓVIL


# Globals
CURRENT_PROJECT = None
GUARDIAN = None


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")  # nosec


# --- ACTIONS (Wrappers simples) ---


def run_nmap(session):
    target = input("\n    🎯 Objetivo (IP/Dominio): ")

    # 1. Ejecutamos el Escáner y CAPTURAMOS el resultado
    scanner = NmapScanner(CURRENT_PROJECT.id, GUARDIAN)
    scan_results = scanner.run(
        target,
        arguments="-T4 -n -Pn --open -p 21,22,80,443,445,3306,8080",
    )

    # 2. Lógica de Neuro-Link (Auto-Exploit)
    if scan_results and isinstance(scan_results, list):
        print(
            f"\n    🔎 Nmap finalizado. Detectados {len(scan_results)} hosts/servicios."
        )

        print("\n    🤔 Analizando inteligencia de amenazas...")
        confirm = input(
            f"    😈 ¿Deseas activar protocolo NEURO-LINK (Auto-Exploit) contra {target}? (s/n): "
        )

        if confirm.lower() == "s":
            print("\n    ⚡ INICIANDO ENLACE NEURAL CON METASPLOIT...")

            # Instanciamos al comandante
            commander = MsfCommander()

            if commander.connect():
                found_targets = False

                for item in scan_results:
                    port = item.get("port")
                    service = item.get("service")

                    if port and service:
                        found_targets = True
                        commander.auto_exploit(target, service, port)

                if not found_targets:
                    print(
                        "    ⚠️ La estructura de datos del escáner no era compatible o no se hallaron servicios mapeados."
                    )
            else:
                print("    ❌ Error: No se pudo conectar con la consola Metasploit.")
        else:
            print("    🔒 Operación ofensiva cancelada.")

    input("\n    Enter...")


def run_msf_console(session):
    print("\n    💀 CONSOLA DE ARTILLERÍA (BEREBRUM-FORCE)")
    commander = MsfCommander()

    if commander.connect():
        ver = commander.get_version()
        print(f"    ✅ Conectado a Metasploit v{ver.get('version')}")

        while True:
            print("\n    [1] Buscar Exploit")
            print("    [2] Ejecutar comando Raw (ej: db_status)")
            print("    [0] Volver")
            op = input("    MSF > ")

            if op == "1":
                term = input("    🔍 Término (ej: eternalblue): ")
                modules = commander.search_module(term)
                print(f"\n    Resultados encontrados: {len(modules)}")
                for m in modules[:10]:
                    print(f"    - {m['type']}/{m['name']}  ({m['rank']})")

            elif op == "2":
                cmd = input("    Comando: ")
                res = commander.send_command(cmd + "\n")
                print("\n" + res)

            elif op == "0":
                break
    else:
        print("    ⚠️ No se pudo establecer enlace con la unidad de fuerza.")

    input("    Enter para volver...")


def run_zap_console(session):
    """Interfaz de control para Web Hunter (OWASP ZAP)"""
    print("\n    🕷️ CONSOLA WEB HUNTER (OWASP ZAP)")
    if not CURRENT_PROJECT:
        print("    ❌ Debes seleccionar un proyecto primero.")
        return

    target = input("    🎯 Target URL (ej: http://testphp.vulnweb.com): ")

    commander = ZapCommander()
    if not commander.connect():
        input("    Enter para volver...")
        return

    while True:
        print(f"\n    --- ZAP CONTROL ({target}) ---")
        print("    [1] 🕸️  Lanzar SPIDER (Mapear Sitio)")
        print("    [2] ⚔️  Lanzar ACTIVE SCAN (Ataque Completo)")
        print("    [3] 📋 Obtener y Guardar Alertas en DB")
        print("    [0] Volver")
        op = input("    ZAP > ")

        if op == "1":
            commander.start_spider(target)
            save_attack_flow(
                session,
                CURRENT_PROJECT.id,
                "ZAP Spider",
                target,
                "Spider Finished",
                "zap.spider.scan()",
            )

        elif op == "2":
            commander.start_active_scan(target)
            save_attack_flow(
                session,
                CURRENT_PROJECT.id,
                "ZAP Active Scan",
                target,
                "Attack Finished",
                "zap.ascan.scan()",
            )

        elif op == "3":
            print("    📥 Descargando hallazgos de ZAP...")
            alerts = commander.get_alerts(target)
            print(f"    🔍 Se encontraron {len(alerts)} alertas en total.")

            count_new = 0
            for a in alerts:
                # Verificamos si ya existe
                exists = (
                    session.query(Finding)
                    .filter_by(
                        project_id=CURRENT_PROJECT.id, title=a["alert"], target=a["url"]
                    )
                    .first()
                )

                if not exists:
                    finding = Finding(
                        project_id=CURRENT_PROJECT.id,
                        title=a["alert"],
                        description=a["description"],
                        severity=a["risk"],
                        solution=a["solution"],
                        evidence=f"Param: {a.get('param', 'N/A')}\nEvidence: {a.get('evidence', 'N/A')}",
                        target=a["url"],
                        vulnerability_name=a["name"],
                    )
                    session.add(finding)
                    count_new += 1

            session.commit()
            print(f"    💾 {count_new} Nuevos hallazgos guardados en la base de datos.")

        elif op == "0":
            break


def run_mobile_scan(session):
    """Interfaz para Mobile Fortress (MobSF)"""
    print("\n    📱 MOBILE FORTRESS (MobSF)")
    commander = MobSFCommander()

    if not commander.is_alive():
        print("    ❌ MobSF no responde en http://127.0.0.1:8000")
        print("    Asegúrate de que el contenedor esté corriendo (docker ps).")
        input("    Enter...")
        return

    if not commander.api_key:
        print("    ⚠️  ATENCIÓN: Necesitas la API Key de MobSF en tu .env")
        input("    Enter para volver...")
        return

    print("    📝 Instrucciones: Introduce la ruta completa al archivo .apk o .ipa")
    file_path = input("    📂 Ruta archivo: ").strip().replace('"', "")

    if not os.path.isfile(file_path):
        print("    ❌ El archivo no existe o la ruta es incorrecta.")
        input("    Enter...")
        return

    result = commander.upload_and_scan(file_path)

    if "error" in result:
        print(f"    ❌ Error: {result['error']}")
    else:
        # Procesar resultados básicos
        score = result.get("average_cvss", "N/A")
        vulns = result.get("security_score", "N/A")
        print(f"\n    📊 REPORTE DE SEGURIDAD GENERADO")
        print(f"       Security Score: {vulns}/100")
        print(f"       CVSS Grade: {score}")
        print("       Hash:", result.get("hash", "N/A"))

        if CURRENT_PROJECT:
            save_attack_flow(
                session,
                CURRENT_PROJECT.id,
                "MobSF Scan",
                os.path.basename(file_path),
                f"Score: {vulns}",
                "mobsf.scan()",
            )

        print(
            "\n    👉 Abre el reporte completo en tu navegador: http://127.0.0.1:8000"
        )

    input("    Enter para volver...")


def run_secret_hunter(session):
    t = input("\n    🎯 Target URL: ")
    tool = SecretHunter(CURRENT_PROJECT.id, GUARDIAN)
    result = tool.run(t)
    print(result)
    save_attack_flow(
        session, CURRENT_PROJECT.id, "SecretHunter", t, result, "requests.get(target)"
    )
    input("\n    Enter...")


def run_ssl_validator(session):
    t = input("\n    🎯 Target URL (https://...): ")
    tool = SSLValidator(CURRENT_PROJECT.id, GUARDIAN)
    result = tool.run(t)
    print(result)
    save_attack_flow(
        session, CURRENT_PROJECT.id, "SSLValidator", t, result, "ssl.wrap_socket"
    )
    input("\n    Enter...")


def run_dashboard():
    print("\n    🚀 Levantando Centro de Comando Avanzado (Streamlit)...")
    dash_path = "dashboard/app.py"

    if os.name == "nt":
        os.system(f"start cmd /k streamlit run {dash_path}")  # nosec
    else:
        try:
            subprocess.Popen(
                ["streamlit", "run", dash_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"    ⚠️ Error lanzando Streamlit: {e}")

    print("    ✅ Dashboard corriendo en segundo plano.")
    print("    👉 Ve a tu navegador y abre: http://localhost:8501")
    input("    Enter para volver al menú...")


def run_arp(session):
    target = input("\n    🎯 IP Víctima (LAN): ")
    gateway = input("    🚪 IP Gateway (Router): ")
    ArpSpoofer(CURRENT_PROJECT.id, GUARDIAN).run(target, gateway_ip=gateway)
    input("\n    Enter...")


def run_cms(session):
    if not CURRENT_PROJECT:
        return
    target = input("\n    🎯 Objetivo (URL): ")
    CMSScanner(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("    Enter para continuar...")


def run_waf_check(session):
    if not CURRENT_PROJECT:
        return
    target = input("\n    🎯 Objetivo (Dominio o URL): ")
    WafDetector(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("    Enter para continuar...")


def run_subdomains(session):
    target = input("\n    🎯 Dominio raíz (ej: google.com): ")
    SubdomainEnum(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_banners(session):
    target = input("\n    🎯 IP Objetivo: ")
    BannerGrabber(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_dirs(session):
    target = input("\n    🎯 Dominio (ej: scanme.nmap.org): ")
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    DirScanner(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_lfi(session):
    target = input("\n    🎯 URL base: ")
    param = input("    ❓ Parámetro (ej: page): ")
    LFIScanner(CURRENT_PROJECT.id, GUARDIAN).run(target, parameter=param)
    input("\n    Enter...")


def run_headers(session):
    target = input("\n    🎯 URL: ")
    HeaderAnalyzer(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_sqli(session):
    target = input("\n    🎯 URL (o dominio para Auto-Discovery): ")
    SQLiScanner(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_xss(session):
    target = input("\n    🎯 URL (o dominio para Auto-Discovery): ")
    XSSScanner(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_ssti(session):
    target = input("\n    🎯 URL con parámetros: ")
    SSTIScanner(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def run_ssh(session):
    target = input("\n    🎯 IP Objetivo: ")
    SSHCracker(CURRENT_PROJECT.id, GUARDIAN).run(target)
    input("\n    Enter...")


def view_findings_table(session):
    findings = session.query(Finding).filter_by(project_id=CURRENT_PROJECT.id).all()
    print(f"\n    [ HALLAZGOS TOTALES: {len(findings)} ]")
    print(f"    {'ID':<4} {'SEVERIDAD':<10} {'NOMBRE'}")
    print("    " + "-" * 40)
    for f in findings:
        name = f.vulnerability_name if f.vulnerability_name else "Unknown"
        print(f"    {f.id:<4} {f.severity:<10} {name}")
    input("\n    Enter...")


def generate_report(session):
    print(f"\n    📝 Generando reporte...")
    res = HtmlReporter(CURRENT_PROJECT.id).generate()
    if res["status"] == "SUCCESS":
        print(f"    ✅ Abriendo: {res['path']}")
        if os.name == "nt":
            os.system(f'start "" "{res["path"]}"')  # nosec
        else:
            os.system(f'xdg-open "{res["path"]}"')  # nosec
    input("\n    Enter...")


# --- AUTOMATION LOGIC ---


def run_dictionary_chain(session):
    if not CURRENT_PROJECT:
        return

    print("\n    🔗 DICTIONARY ATTACK CHAIN")
    print("    --------------------------")
    domain = input("    🎯 Dominio Objetivo (ej: testphp.vulnweb.com): ")
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    # --- FASE 1: Rutas ---
    print(f"\n    [FASE 1/3] 📂 Buscando archivos .php, .asp, etc...")
    dir_tool = DirScanner(CURRENT_PROJECT.id, GUARDIAN)
    dir_result = dir_tool.run(domain)

    raw_paths = dir_result.get("found_urls", [])
    candidates = []
    for url in raw_paths:
        if not any(ext in url for ext in [".jpg", ".png", ".css", ".js", ".gif"]):
            candidates.append(url)

    if not candidates:
        print("    ❌ No se encontraron rutas interesantes. Fin de la cadena.")
        input("    Enter...")
        return

    # --- FASE 2: Minería ---
    print(f"\n    [FASE 2/3] ⛏️ Buscando parámetros en {len(candidates)} rutas...")
    miner_tool = ParamMiner(CURRENT_PROJECT.id, GUARDIAN)
    attack_surface = []

    for url in candidates:
        res = miner_tool.run(url)
        found = res.get("found_urls", [])
        if found:
            attack_surface.extend(found)

    if not attack_surface:
        print("    ⚠️ No se encontraron parámetros. Probando rutas base...")
        attack_surface = candidates

    # --- FASE 3: Ataque ---
    print(
        f"\n    [FASE 3/3] ⚔️ Lanzando Arsenal contra {len(attack_surface)} objetivos..."
    )

    sqli_tool = SQLiScanner(CURRENT_PROJECT.id, GUARDIAN)
    xss_tool = XSSScanner(CURRENT_PROJECT.id, GUARDIAN)
    ssti_tool = SSTIScanner(CURRENT_PROJECT.id, GUARDIAN)

    for target in attack_surface:
        print(f"\n    👉 Targeting: {target}")
        sqli_tool.run(target)
        xss_tool.run(target)
        ssti_tool.run(target)

    print("\n    ✅ Cadena Finalizada. Revisa el Attack Flow.")
    input("    Enter para continuar...")


# --- PROJECT MANAGEMENT ---


def create_project(session):
    name = input("\n    Nombre: ")
    scope = input("    Scope (IPs, Dominios): ")
    try:
        p = Project(name=name, scope_cidrs=scope)
        session.add(p)
        session.commit()
        return p
    except Exception as e:
        print(f"    ❌ Error creando proyecto: {e}")
        session.rollback()
        input("    Enter...")
        return None


def load_project(session):
    projects = session.query(Project).all()
    print("\n    --- PROYECTOS ---")
    for p in projects:
        print(f"    {p.id}. {p.name}")
    try:
        pid = int(input("\n    ID: "))
        return session.query(Project).filter_by(id=pid).first()
    except:
        return None


# --- MAIN LOOP ---


def main():
    global CURRENT_PROJECT, GUARDIAN
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()

    while True:
        clear_screen()
        print("\n    💀 BEREBRUM 3.0 - RED TEAM FRAMEWORK")  # ¡VERSIÓN 3.0!

        if CURRENT_PROJECT:
            print(f"    📂 Proyecto: {CURRENT_PROJECT.name}")
            print("    " + "-" * 40)

            print("    [ 🚀 AUTOMATIZACIÓN ]")
            print("    00.⛓️ Dictionary Attack Chain")

            print("    [ RECONOCIMIENTO ]")
            print("    1. 📡 Nmap Port Scan")
            print("    2. 🛡️ WAF Detector")
            print("    3. 🌐 Subdomain Enumeration")
            print("    4. 🔎 CMS Fingerprinter")
            print("    5. 🏷️ Banner Grabbing")
            print("    6. 📂 Directory Fuzzing")

            print("    [ WEB OWASP ]")
            print("    7. 🌪️ LFI Fuzzer")
            print("    8. 🕵️ Header Analyzer")
            print("    9. 💉 SQL Injection")
            print("    10. 🎭 XSS Reflected")
            print("    11. 🧠 SSTI Scanner")
            print("    12. 🕵️ Secret Hunter (API Keys)")
            print("    13. 🔒 SSL/TLS Validator")

            print("    [ INTERFACES EXTERNAS ]")
            print("    20. 🧨 METASPLOIT INTERFACE")
            print("    21. 🕷️ WEB HUNTER (ZAP CONSOLE)")
            print("    22. 📱 MOBILE FORTRESS (APK/IPA)")  # <--- LISTO

            print("    [ NETWORK ]")
            print("    14. 🔓 SSH Brute Force")
            print("    15. ☠️ ARP Spoofing (MITM)")

            print("    [ INTELLIGENCE & REPORT ]")
            print("    16. ⚔️ ATTACK FLOW (Timeline)")
            print("    17. 📊 Tabla Simple")
            print("    18. 📄 Reporte HTML")
            print("    19. 🖥️ WEB DASHBOARD (Lanzar)")

            print("    " + "-" * 40)
            print("    0. 🔙 Salir / Cerrar Proyecto")
        else:
            print("    1. 🆕 Nuevo Proyecto")
            print("    2. 📂 Cargar Proyecto")
            print("    3. 🖥️  WEB DASHBOARD")
            print("    0. 🚪 Salir")

        op = input("\n    > ")

        if not CURRENT_PROJECT:
            if op == "1":
                p = create_project(session)
                if p:
                    CURRENT_PROJECT = p
                    GUARDIAN = ScopeGuardian(p.scope_cidrs.split(","))
            elif op == "2":
                p = load_project(session)
                if p:
                    CURRENT_PROJECT = p
                    GUARDIAN = ScopeGuardian(
                        [s.strip() for s in p.scope_cidrs.split(",")]
                    )
            elif op == "3":
                run_dashboard()
            elif op == "0":
                break
        else:
            if op == "00":
                run_dictionary_chain(session)
            elif op == "1":
                run_nmap(session)
            elif op == "2":
                run_waf_check(session)
            elif op == "3":
                run_subdomains(session)
            elif op == "4":
                run_cms(session)
            elif op == "5":
                run_banners(session)
            elif op == "6":
                run_dirs(session)
            elif op == "7":
                run_lfi(session)
            elif op == "8":
                run_headers(session)
            elif op == "9":
                run_sqli(session)
            elif op == "10":
                run_xss(session)
            elif op == "11":
                run_ssti(session)
            elif op == "12":
                run_secret_hunter(session)
            elif op == "13":
                run_ssl_validator(session)
            elif op == "14":
                run_ssh(session)
            elif op == "15":
                run_arp(session)
            elif op == "16":
                view_attack_flow(CURRENT_PROJECT.id)
            elif op == "17":
                view_findings_table(session)
            elif op == "18":
                generate_report(session)
            elif op == "19":
                run_dashboard()
            elif op == "20":
                run_msf_console(session)
            elif op == "21":
                run_zap_console(session)
            elif op == "22":
                run_mobile_scan(session)
            elif op == "0":
                CURRENT_PROJECT = None


if __name__ == "__main__":
    main()
