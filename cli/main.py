"""
Berebrum - CLI Principal
Interfaz de línea de comandos interactiva con herramientas integradas
"""

import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

try:
    from InquirerPy import prompt
except ImportError:
    print("ERROR: InquirerPy no está instalado")
    print("Ejecuta: pip install -r requirements.txt")
    sys.exit(1)

from core.database import db_manager
from tools.ssti_detector import SSTIDetector
from tools.reflection_analyzer import ReflectionAnalyzer
from tools.lfi_rfi_scanner import LFIRFIScanner

console = Console()


class BerebrumCLI:
    def __init__(self):
        self.current_project = None
        db_manager.init_db()

    def show_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🧠 BEREBRUM - AI-Powered Red Team Platform              ║
║                                                           ║
║   [MITRE ATT&CK] [CVSS 3.1] [MCP Protocol] [AI Engine]    ║
║                                                           ║
║   📦 12 Herramientas | 3 Categorías | 3 Modos             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

⚠️  ADVERTENCIA: Solo para pentesting autorizado
   El uso no autorizado es ILEGAL
        """
        console.print(banner, style="bold cyan")

    def run(self):
        self.show_banner()

        while True:
            try:
                if not self.current_project:
                    action = self._show_main_menu()

                    if action == "new_project":
                        self._create_project()
                    elif action == "load_project":
                        self._load_project()
                    elif action == "list_projects":
                        self._list_projects()
                    elif action == "exit":
                        console.print("\n[yellow]¡Hasta luego![/yellow]")
                        break
                else:
                    action = self._show_project_menu()

                    if action == "view_info":
                        self._view_project_info()
                    elif action == "run_scan":
                        self._run_scan()
                    elif action == "view_logs":
                        self._view_logs()
                    elif action == "view_vulns":
                        self._view_vulnerabilities()
                    elif action == "back":
                        self.current_project = None
                    elif action == "exit":
                        console.print("\n[yellow]¡Hasta luego![/yellow]")
                        break

            except KeyboardInterrupt:
                console.print("\n\n[yellow]Operación cancelada[/yellow]")
                continue
            except Exception as e:
                console.print(f"\n[red]Error: {str(e)}[/red]")
                continue

    def _show_main_menu(self):
        questions = [
            {
                "type": "list",
                "name": "action",
                "message": "¿Qué deseas hacer?",
                "choices": [
                    {"name": "🆕 Crear Nuevo Proyecto", "value": "new_project"},
                    {"name": "📂 Cargar Proyecto Existente", "value": "load_project"},
                    {"name": "📋 Listar Todos los Proyectos", "value": "list_projects"},
                    {"name": "🚪 Salir", "value": "exit"},
                ],
            }
        ]
        answers = prompt(questions)
        return answers["action"]

    def _show_project_menu(self):
        console.print(
            f"\n[bold green]Proyecto Activo:[/bold green] {self.current_project.name}"
        )

        questions = [
            {
                "type": "list",
                "name": "action",
                "message": "Selecciona una operación:",
                "choices": [
                    {"name": "📊 Ver Información del Proyecto", "value": "view_info"},
                    {"name": "🔍 Ejecutar Escaneo", "value": "run_scan"},
                    {"name": "📋 Ver Logs", "value": "view_logs"},
                    {"name": "🔴 Ver Vulnerabilidades", "value": "view_vulns"},
                    {"name": "🔙 Volver al Menú Principal", "value": "back"},
                    {"name": "🚪 Salir", "value": "exit"},
                ],
            }
        ]
        answers = prompt(questions)
        return answers["action"]

    def _create_project(self):
        console.print("\n[bold cyan]═══ CREAR NUEVO PROYECTO ═══[/bold cyan]")

        questions = [
            {
                "type": "input",
                "name": "name",
                "message": "Nombre del Proyecto:",
                "validate": lambda x: len(x) > 0 or "El nombre no puede estar vacío",
            },
            {
                "type": "input",
                "name": "scope",
                "message": "Scope Autorizado (IPs/Redes):",
                "default": "192.168.1.0/24",
                "validate": lambda x: len(x) > 0 or "El scope no puede estar vacío",
            },
            {
                "type": "input",
                "name": "description",
                "message": "Descripción (opcional):",
            },
        ]

        answers = prompt(questions)

        try:
            project = db_manager.create_project(
                name=answers["name"],
                scope_ips=answers["scope"],
                description=answers["description"] if answers["description"] else None,
            )

            console.print(f"\n[green]✓[/green] Proyecto creado: {project.name}")
            console.print(f"[green]✓[/green] Scope: {project.scope_ips}")

            self.current_project = project

        except Exception as e:
            error_msg = str(e)

            if "UNIQUE constraint failed: projects.name" in error_msg:
                console.print(
                    f"\n[red]✗[/red] Ya existe un proyecto con el nombre '{answers['name']}'"
                )
                console.print("[yellow]Por favor, elige otro nombre[/yellow]")
            else:
                console.print(f"[red]✗[/red] Error: {e}")

    def _load_project(self):
        projects = db_manager.list_projects(status="active")

        if not projects:
            console.print("[yellow]No hay proyectos activos[/yellow]")
            return

        choices = [{"name": f"{p.name} (ID: {p.id})", "value": p.id} for p in projects]

        questions = [
            {
                "type": "list",
                "name": "project_id",
                "message": "Selecciona un proyecto:",
                "choices": choices,
            }
        ]

        answers = prompt(questions)
        project = db_manager.get_project(answers["project_id"])
        self.current_project = project

        console.print(f"\n[green]✓[/green] Proyecto cargado: {project.name}")

    def _list_projects(self):
        projects = db_manager.list_projects()

        if not projects:
            console.print("[yellow]No hay proyectos[/yellow]")
            return

        table = Table(title="Todos los Proyectos", box=box.ROUNDED)
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Nombre", style="green")
        table.add_column("Scope", style="yellow")
        table.add_column("Estado", style="magenta", justify="center")

        for p in projects:
            scope_display = (
                p.scope_ips[:40] + "..." if len(p.scope_ips) > 40 else p.scope_ips
            )
            table.add_row(str(p.id), p.name, scope_display, p.status)

        console.print(table)

    def _view_project_info(self):
        p = self.current_project
        stats = db_manager.get_project_stats(p.id)

        info_panel = f"""
[bold]Nombre:[/bold] {p.name}
[bold]ID:[/bold] {p.id}
[bold]Estado:[/bold] {p.status}
[bold]Scope:[/bold] {p.scope_ips}
[bold]Creado:[/bold] {p.created_at.strftime('%Y-%m-%d %H:%M')}

[bold cyan]Estadísticas:[/bold cyan]
  Total Logs: {stats['total_logs']}
  Vulnerabilidades: {stats['total_vulnerabilities']}
    🔴 Críticas: {stats['critical']}
    🟠 Altas: {stats['high']}
    🟡 Medias: {stats['medium']}
    🟢 Bajas: {stats['low']}
  
  Herramientas Usadas: {stats.get('tools_used', 0)}
  Tasa de Éxito: {int((stats.get('successful_logs', 0) / stats['total_logs'] * 100)) if stats['total_logs'] > 0 else 0}%
        """

        console.print(
            Panel(info_panel, title="📊 Información del Proyecto", border_style="green")
        )

    def _normalize_target(self, target: str, tool_id: str) -> str:
        """Normalizar target agregando protocolo si es necesario"""
        import re

        target = target.strip()
        web_tools = ["web_dir_scanner", "header_analyzer", "vuln_scanner"]

        if target.startswith(("http://", "https://")):
            return target

        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, target):
            if tool_id in web_tools:
                console.print(
                    f"[yellow]→[/yellow] Auto-agregando http:// a IP: {target}"
                )
                return f"http://{target}"
            return target

        if target.lower() in ["localhost", "127.0.0.1"]:
            if tool_id in web_tools:
                console.print(f"[yellow]→[/yellow] Auto-agregando http:// a localhost")
                return f"http://{target}"
            return target

        domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$"
        if re.match(domain_pattern, target):
            if tool_id in web_tools:
                console.print(
                    f"[yellow]→[/yellow] Auto-agregando https:// a dominio: {target}"
                )
                return f"https://{target}"
            return target

        return target

    def _run_scan(self):
        """Menú de herramientas de escaneo - ACTUALIZADO con categorías"""

        # Primero seleccionar categoría
        category_choices = [
            {"name": "🔍 Reconocimiento (8 herramientas)", "value": "recon"},
            {"name": "💥 Explotación OWASP (5 herramientas)", "value": "exploit"},
            {"name": "🔓 Fuerza Bruta (1 herramienta)", "value": "brute_force"},
            {"name": "← Volver", "value": "back"},
        ]

        category_question = [
            {
                "type": "list",
                "name": "category",
                "message": "Selecciona una categoría:",
                "choices": category_choices,
            }
        ]

        category_answer = prompt(category_question)

        if category_answer["category"] == "back":
            return

        # Mostrar herramientas según categoría
        tool_choices = []

        if category_answer["category"] == "recon":
            tool_choices = [
                {"name": "🔍 Port Scanner (Quick)", "value": "port_scanner_quick"},
                {"name": "🔍 Port Scanner (Full)", "value": "port_scanner_full"},
                {"name": "📡 Service Banner Grabber", "value": "banner_grabber"},
                {"name": "🌐 Subdomain Enumerator", "value": "subdomain_enum"},
                {"name": "📁 Web Directory Scanner", "value": "web_dir_scanner"},
                {"name": "📋 HTTP Header Analyzer", "value": "header_analyzer"},
                {"name": "🔎 DNS Information Gatherer", "value": "dns_gatherer"},
                {"name": "🔒 SSL/TLS Analyzer", "value": "ssl_analyzer"},
                {"name": "⚠️  Vulnerability Scanner", "value": "vuln_scanner"},
                {"name": "← Volver", "value": "back"},
            ]
        elif category_answer["category"] == "exploit":
            tool_choices = [
                {
                    "name": "💉 SQL Injection Scanner [MITRE: T1190]",
                    "value": "sqli_scanner",
                },
                {
                    "name": "⚡ XSS Detector (Reflected/Stored/DOM) [MITRE: T1189]",
                    "value": "xss_detector",
                },
                {
                    "name": "💉 SSTI Detector (7 Engines + RCE) [MITRE: T1190]",  # ← NUEVO
                    "value": "ssti_detector",
                },
                {
                    "name": "🔍 Reflection Analyzer (XSS/Info Disclosure)",
                    "value": "reflection_analyzer",
                },
                {
                    "name": "🗂️  LFI/RFI Scanner (File Inclusion) [MITRE: T1083]",
                    "value": "lfi_rfi_scanner",
                },
                {
                    "name": "🛡️  CSRF Tester [MITRE: T1184]",
                    "value": "csrf_tester",
                },
                {"name": "← Volver", "value": "back"},
            ]
        elif category_answer["category"] == "brute_force":
            tool_choices = [
                {
                    "name": "🔓 SSH Brute Force [MITRE: T1110.001]",
                    "value": "ssh_brute",
                },
                {"name": "← Volver", "value": "back"},
            ]

        questions = [
            {
                "type": "list",
                "name": "tool",
                "message": "Selecciona herramienta:",
                "choices": tool_choices,
            }
        ]

        answers = prompt(questions)

        if answers["tool"] == "back":
            return

        # Ejecutar herramienta seleccionada
        self._execute_tool(answers["tool"])

    def _execute_tool(self, tool_id: str):
        """Ejecutar una herramienta específica - ACTUALIZADO con nuevas herramientas"""

        from tools.executor import ToolExecutor

        # Importar herramientas según categoría
        tools_available = {}

        # === RECONNAISSANCE ===
        try:
            from tools.recon.port_scanner import scan_target

            tools_available["scan_target"] = scan_target
        except ImportError as e:
            console.print(f"[yellow]Warning: Port Scanner no disponible: {e}[/yellow]")

        try:
            from tools.recon.banner_grabber import BannerGrabber

            tools_available["BannerGrabber"] = BannerGrabber
        except ImportError:
            pass

        try:
            from tools.recon.subdomain_enum import enumerate_subdomains

            tools_available["enumerate_subdomains"] = enumerate_subdomains
        except ImportError:
            pass

        try:
            from tools.recon.web_dir_scanner import scan_web_directories

            tools_available["scan_web_directories"] = scan_web_directories
        except ImportError:
            pass

        try:
            from tools.recon.header_analyzer import analyze_headers

            tools_available["analyze_headers"] = analyze_headers
        except ImportError:
            pass

        try:
            from tools.recon.dns_gatherer import gather_dns_info

            tools_available["gather_dns_info"] = gather_dns_info
        except ImportError:
            pass

        try:
            from tools.recon.ssl_analyzer import analyze_ssl

            tools_available["analyze_ssl"] = analyze_ssl
        except ImportError:
            pass

        try:
            from tools.recon.vuln_scanner import scan_vulnerabilities

            tools_available["scan_vulnerabilities"] = scan_vulnerabilities
        except ImportError:
            pass

        # === EXPLOITATION ===
        try:
            from tools.exploit.sqli_scanner import scan_sqli

            tools_available["scan_sqli"] = scan_sqli
        except ImportError:
            pass

        try:
            from tools.exploit.xss_detector import scan_xss

            tools_available["scan_xss"] = scan_xss
        except ImportError:
            pass
        try:
            #             from tools.ssti_detector_old import SSTIDetector  # ← NUEVO

            tools_available["SSTIDetector"] = SSTIDetector
        except ImportError:
            pass
        try:
            from tools.exploit.csrf_tester import scan_csrf

            tools_available["scan_csrf"] = scan_csrf
        except ImportError:
            pass

        # === BRUTE FORCE ===
        try:
            from tools.brute_force.ssh_brute import brute_force_ssh

            tools_available["brute_force_ssh"] = brute_force_ssh
        except ImportError:
            pass

        # === CORE ===
        try:
            from core.scan_modes import ScanModeManager

            tools_available["ScanModeManager"] = ScanModeManager
        except ImportError:
            pass

        if not tools_available:
            console.print("[red]No hay herramientas disponibles[/red]")
            return

        # Solicitar target
        target_question = [
            {
                "type": "input",
                "name": "target",
                "message": "Target (IP/URL/Domain):",
                "validate": lambda x: len(x) > 0 or "El target no puede estar vacío",
            }
        ]
        target_answer = prompt(target_question)
        target = target_answer["target"]

        # Normalizar target
        target = self._normalize_target(target, tool_id)

        # Solicitar modo de escaneo si está disponible y la herramienta lo soporta
        scan_mode = None
        tools_with_modes = [
            "sqli_scanner",
            "xss_detector",
            "csrf_tester",
            "ssh_brute",
        ]

        if tool_id in tools_with_modes and "ScanModeManager" in tools_available:
            modes = ScanModeManager.list_modes()
            mode_choices = [
                {
                    "name": f"{info['name']} - {info['description']}",
                    "value": mode_id,
                }
                for mode_id, info in modes.items()
            ]

            mode_question = [
                {
                    "type": "list",
                    "name": "scan_mode",
                    "message": "Selecciona el modo de escaneo:",
                    "choices": mode_choices,
                }
            ]

            mode_answer = prompt(mode_question)
            scan_mode = mode_answer["scan_mode"]

        # Crear executor
        executor = ToolExecutor(self.current_project.id)

        # Mapear tool_id a función y configuración
        tool_map = {}

        # RECONNAISSANCE
        if "scan_target" in tools_available:
            tool_map["port_scanner_quick"] = {
                "name": "Port Scanner",
                "function": tools_available["scan_target"],
                "kwargs": {"scan_type": "quick"},
            }
            tool_map["port_scanner_full"] = {
                "name": "Port Scanner",
                "function": tools_available["scan_target"],
                "kwargs": {"scan_type": "full"},
                "warning": "⚠️  Escaneo completo puede tomar mucho tiempo",
            }

        if "BannerGrabber" in tools_available:
            tool_map["banner_grabber"] = {
                "name": "Banner Grabber",
                "function": lambda t, **k: self._run_banner_grabber(
                    t, tools_available["BannerGrabber"]
                ),
                "kwargs": {},
            }

        if "enumerate_subdomains" in tools_available:
            tool_map["subdomain_enum"] = {
                "name": "Subdomain Enumerator",
                "function": tools_available["enumerate_subdomains"],
                "kwargs": {"quick": True},
            }

        if "scan_web_directories" in tools_available:
            tool_map["web_dir_scanner"] = {
                "name": "Web Directory Scanner",
                "function": tools_available["scan_web_directories"],
                "kwargs": {"quick": True},
            }

        if "analyze_headers" in tools_available:
            tool_map["header_analyzer"] = {
                "name": "HTTP Header Analyzer",
                "function": tools_available["analyze_headers"],
                "kwargs": {},
            }

        if "gather_dns_info" in tools_available:
            tool_map["dns_gatherer"] = {
                "name": "DNS Information Gatherer",
                "function": tools_available["gather_dns_info"],
                "kwargs": {},
            }

        if "analyze_ssl" in tools_available:
            tool_map["ssl_analyzer"] = {
                "name": "SSL/TLS Analyzer",
                "function": tools_available["analyze_ssl"],
                "kwargs": {},
            }

        if "scan_vulnerabilities" in tools_available:
            tool_map["vuln_scanner"] = {
                "name": "Vulnerability Scanner",
                "function": tools_available["scan_vulnerabilities"],
                "kwargs": {},
                "warning": "⚠️  Esta herramienta puede ser intrusiva",
            }

        # EXPLOITATION
        if "scan_sqli" in tools_available:
            tool_map["sqli_scanner"] = {
                "name": "SQL Injection Scanner",
                "function": tools_available["scan_sqli"],
                "kwargs": {"scan_mode": scan_mode} if scan_mode else {},
                "warning": "⚠️  Esta herramienta puede ser intrusiva",
            }

        if "scan_xss" in tools_available:
            tool_map["xss_detector"] = {
                "name": "XSS Detector",
                "function": tools_available["scan_xss"],
                "kwargs": {"scan_mode": scan_mode} if scan_mode else {},
            }
        if "SSTIDetector" in tools_available:
            tool_map["ssti_detector"] = {
                "name": "SSTI Detector",
                "function": lambda t, **k: self._run_ssti_detector(
                    t, tools_available["SSTIDetector"], scan_mode
                ),
                "kwargs": {},
                "reflection_analyzer": {
                    "name": "🔍 Reflection Analyzer (XSS/Info Disclosure)",
                    "function": run_reflection_analyzer,
                    "description": "Detecta payload reflection en JavaScript, HTML y otros contextos",
                },
                "warning": "⚠️  Esta herramienta detecta RCE - puede ser intrusiva",
            }

            # REFLECTION ANALYZER
            tool_map["reflection_analyzer"] = {
                "name": "🔍 Reflection Analyzer",
                "function": lambda t, **k: (
                    run_reflection_analyzer(self.current_project.id, t)
                    if self.current_project
                    else None
                ),
                "kwargs": {},
            }

            # LFI/RFI SCANNER
            tool_map["lfi_rfi_scanner"] = {
                "name": "🗂️  LFI/RFI Scanner",
                "function": lambda t, **k: (
                    run_lfi_rfi_scanner(self.current_project.id, t)
                    if self.current_project
                    else None
                ),
                "kwargs": {},
            }

        if "scan_csrf" in tools_available:
            tool_map["csrf_tester"] = {
                "name": "CSRF Tester",
                "function": tools_available["scan_csrf"],
                "kwargs": {"scan_mode": scan_mode} if scan_mode else {},
            }

        # BRUTE FORCE
        if "brute_force_ssh" in tools_available:
            tool_map["ssh_brute"] = {
                "name": "SSH Brute Force",
                "function": lambda t, **k: self._run_ssh_brute(
                    t, tools_available["brute_force_ssh"], scan_mode
                ),
                "kwargs": {},
                "warning": "⚠️  Ataque de fuerza bruta puede causar bloqueos",
            }

        tool_config = tool_map.get(tool_id)
        if not tool_config:
            console.print("[red]Herramienta no implementada[/red]")
            return

        # Mostrar advertencia si existe
        if "warning" in tool_config:
            console.print(f"\n[yellow]{tool_config['warning']}[/yellow]")
            confirm = prompt(
                [
                    {
                        "type": "confirm",
                        "name": "continue",
                        "message": "¿Continuar?",
                        "default": False,
                    }
                ]
            )
            if not confirm["continue"]:
                return

        # Ejecutar con progress bar
        console.print(f"\n[cyan]Ejecutando {tool_config['name']}...[/cyan]")
        if scan_mode:
            console.print(f"[cyan]Modo: {scan_mode}[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Escaneando {target}...", total=None)

            result = executor.execute(
                tool_config["name"],
                tool_config["function"],
                target,
                **tool_config["kwargs"],
            )

            progress.update(task, completed=True)

        # Mostrar resultados
        # self._display_scan_results(result, tool_config["name"])

    def _run_banner_grabber(self, target: str, BannerGrabber):
        """Wrapper para banner grabber que solicita puertos"""
        ports_question = [
            {
                "type": "input",
                "name": "ports",
                "message": "Puertos a escanear (separados por coma):",
                "default": "21,22,23,80,443,3306,3389",
            }
        ]
        ports_answer = prompt(ports_question)
        ports = [int(p.strip()) for p in ports_answer["ports"].split(",")]

        grabber = BannerGrabber()
        return grabber.scan_multiple_ports(target, ports)

    def _run_ssh_brute(self, target: str, brute_force_ssh, scan_mode):
        """Wrapper para SSH brute force con parámetros adicionales"""
        port_question = [
            {
                "type": "input",
                "name": "port",
                "message": "Puerto SSH:",
                "default": "22",
            }
        ]
        port_answer = prompt(port_question)
        port = int(port_answer["port"])

        # Preguntar por wordlists
        wordlist_question = [
            {
                "type": "confirm",
                "name": "use_wordlist",
                "message": "¿Usar wordlists personalizadas?",
                "default": False,
            }
        ]
        wordlist_answer = prompt(wordlist_question)

        kwargs = {"port": port}

        if scan_mode:
            kwargs["scan_mode"] = scan_mode

        if wordlist_answer["use_wordlist"]:
            files_question = [
                {
                    "type": "input",
                    "name": "username_file",
                    "message": "Archivo de usuarios (Enter para skip):",
                },
                {
                    "type": "input",
                    "name": "password_file",
                    "message": "Archivo de contraseñas (Enter para skip):",
                },
            ]
            files_answer = prompt(files_question)

            if files_answer["username_file"]:
                kwargs["username_file"] = files_answer["username_file"]
            if files_answer["password_file"]:
                kwargs["password_file"] = files_answer["password_file"]

        return brute_force_ssh(target, **kwargs)

    def _run_ssti_detector(self, target: str, SSTIDetector, scan_mode):
        """SSTI Detector v3.2 - DUAL MODE"""
        try:
            from tools.ssti_detector import SSTIDetector as Detector
            import json

            console.print("\n[bold red]💉 SSTI DETECTOR v3.2 - DUAL MODE[/bold red]\n")
            console.print("[yellow]Phase 1: SSTImap (SSTI real/RCE)[/yellow]")
            console.print(
                "[yellow]Phase 2: Native (Reflection/Info Disclosure)[/yellow]\n"
            )

            detector = Detector(timeout=10.0, mode="dual")

            if detector.sstimap_available:
                console.print("[green]✅ SSTImap disponible[/green]")
            else:
                console.print("[yellow]⚠️  Solo modo nativo[/yellow]")

            deep_scan = scan_mode == "deep"

            console.print(f"\n[green]🚀 Escaneando {target}...[/green]\n")

            result = detector.scan(target, deep_scan=deep_scan)

            console.print(f"\n{'='*70}\n[bold]RESULTADOS[/bold]\n{'='*70}\n")

            if result["vulnerable"]:
                console.print("[bold red]🚨 VULNERABLE[/bold red]")
            else:
                console.print("[bold green]✅ SEGURO[/bold green]")

            console.print(
                f"Vulnerabilidades: [yellow]{result['vulnerability_count']}[/yellow]"
            )
            console.print(f"Modo: DUAL (SSTImap + Native)")
            console.print(f"Duration: {result.get('scan_duration', 0):.1f}s")
            console.print(f"Severity: {result.get('severity')}")

            if result["vulnerabilities"]:
                console.print(f"\n[yellow]📋 Detalle:[/yellow]\n")
                for i, v in enumerate(result["vulnerabilities"], 1):
                    console.print(f"[bold]{i}. {v['subtype']}[/bold]")
                    console.print(
                        f"   Tool: [green]{v.get('tool', 'unknown').upper()}[/green]"
                    )
                    console.print(f"   CVSS: [red]{v['cvss_score']}[/red]")
                    console.print(f"   Type: {v['type']}")
                    console.print("")

            return result

        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
            import traceback

            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return {"vulnerable": False, "error": str(e)}

        # def _run_reflection_analyzer(self, target: str, **kwargs):
        # """Reflection Analyzer - Detecta payload reflection"""
        # try:
        # from tools.reflection_analyzer import ReflectionAnalyzer as Analyzer
        # import json
        # from urllib.parse import urlparse, parse_qs
        #     # console.print("\n[bold cyan]🔍 REFLECTION ANALYZER v1.0[/bold cyan]\n")
        # console.print("[yellow]Payload Reflection Detection[/yellow]\n")
        #             # Parse URL
        # parsed = urlparse(target)
        # params = parse_qs(parsed.query)
        #     # if not params:
        # console.print("[red]❌ URL debe tener parámetros[/red]")
        # console.print("[yellow]Ejemplo: http://site.com?name=test[/yellow]")
        # return {"vulnerable": False, "error": "No parameters"}
        #             # Obtener parámetro
        # param_list = list(params.keys())
        # param = param_list[0]  # Usar el primero por defecto
        #     # console.print(f"[cyan]Parámetro a probar: {param}[/cyan]")
        # console.print(f"[dim]URL: {target}[/dim]\n")
        #             # Crear analyzer
        # analyzer = Analyzer(timeout=10.0)
        #             # Ejecutar scan
        # console.print("[green]🚀 Iniciando escaneo...[/green]\n")
        #     # result = analyzer.scan(target, parameter=param)
        #             # Mostrar resultados
        # console.print(f"\n{'='*70}")
        # console.print("[bold]RESULTADOS[/bold]")
        # console.print(f"{'='*70}\n")
        #     # if result['vulnerable']:
        # console.print("[bold red]🚨 VULNERABLE[/bold red]")
        # else:
        # console.print("[bold green]✅ NO VULNERABLE[/bold green]")
        #     # console.print(f"Vulnerabilidades: [yellow]{result['vulnerability_count']}[/yellow]")
        # console.print(f"Severity: [red]{result['severity']}[/red]")
        # console.print(f"Confidence: [green]{result['confidence']}%[/green]")
        # console.print(f"Duration: [yellow]{result.get('scan_duration', 0):.1f}s[/yellow]")
        # console.print(f"Requests: [yellow]{result.get('total_requests', 0)}[/yellow]")
        #     # if result['vulnerabilities']:
        # console.print(f"\n[bold yellow]📋 Vulnerabilidades detectadas:[/bold yellow]\n")
        #     # for i, v in enumerate(result['vulnerabilities'], 1):
        # console.print(f"[bold]{i}. {v['subtype']}[/bold]")
        # console.print(f"   Parameter: [cyan]{v['parameter']}[/cyan]")
        # console.print(f"   Context: [yellow]{v['context']}[/yellow]")
        # console.print(f"   CVSS: [red]{v['cvss_score']}[/red]")
        # console.print(f"   CWE: {v['cwe_id']}")
        # console.print("")
        #     # console.print(f"\n{'='*70}\n")
        #     # return result
        #     # except Exception as e:
        # console.print(f"[red]❌ Error: {e}[/red]")
        # import traceback
        # console.print(f"[dim]{traceback.format_exc()}[/dim]")
        # return {"vulnerable": False, "error": str(e)}
        #     def _display_scan_results(self, result: dict, tool_name: str):
        """Mostrar resultados del escaneo"""

        if result.get("blocked"):
            console.print(f"\n[red]✗ Escaneo bloqueado: {result.get('error')}[/red]")
            return

        if not result.get("success", True) and "error" in result:
            console.print(f"\n[red]✗ Error en escaneo: {result['error']}[/red]")
            return

        if "execution_metadata" in result:
            metadata = result["execution_metadata"]
            console.print(
                f"\n[green]✓ Escaneo completado en {metadata['duration']:.2f}s[/green]"
            )

        # Mostrar resultados según el tipo de herramienta
        if tool_name == "Port Scanner":
            self._display_port_scan_results(result)
        elif tool_name == "Banner Grabber":
            self._display_banner_results(result)
        elif tool_name == "Subdomain Enumerator":
            self._display_subdomain_results(result)
        elif tool_name == "Web Directory Scanner":
            self._display_webdir_results(result)
        elif tool_name == "HTTP Header Analyzer":
            self._display_header_results(result)
        elif tool_name == "DNS Information Gatherer":
            self._display_dns_results(result)
        elif tool_name == "SSL/TLS Analyzer":
            self._display_ssl_results(result)
        elif tool_name == "Vulnerability Scanner":
            self._display_vuln_scan_results(result)
        elif tool_name == "SQL Injection Scanner":
            self._display_sqli_results(result)
        elif tool_name == "XSS Detector":
            self._display_xss_results(result)
        elif tool_name == "SSTI Detector":
            self._display_ssti_results(result)
        elif tool_name == "CSRF Tester":
            self._display_csrf_results(result)
        elif tool_name == "SSH Brute Force":
            self._display_ssh_brute_results(result)
        else:
            console.print(Panel(str(result), title="Resultados", border_style="cyan"))

    # === NUEVOS MÉTODOS DE DISPLAY PARA HERRAMIENTAS OWASP Y BRUTE FORCE ===

    def _display_sqli_results(self, result: dict):
        """Mostrar resultados de SQLi Scanner"""
        console.print(
            f"\n[bold]Vulnerable: {'🚨 Sí' if result.get('vulnerable') else '✅ No'}[/bold]"
        )
        console.print(
            f"[bold]Base de Datos: {result.get('database_type', 'Desconocida')}[/bold]"
        )
        console.print(f"[bold]Confianza: {result.get('confidence', 0)}%[/bold]\n")

        if result.get("vulnerabilities"):
            table = Table(title="Vulnerabilidades SQL Injection", box=box.ROUNDED)
            table.add_column("Parámetro", style="cyan")
            table.add_column("Técnica", style="yellow")
            table.add_column("Payload", style="red")
            table.add_column("Severidad", style="magenta")

            for vuln in result["vulnerabilities"][:10]:
                table.add_row(
                    vuln.get("parameter", "N/A"),
                    vuln.get("technique", "N/A"),
                    vuln.get("payload", "N/A")[:50] + "...",
                    vuln.get("severity", "N/A"),
                )

            console.print(table)

    def _display_xss_results(self, result: dict):
        """Mostrar resultados de XSS Detector"""
        console.print(
            f"\n[bold]Vulnerable: {'🚨 Sí' if result.get('vulnerable') else '✅ No'}[/bold]\n"
        )

        if result.get("vulnerabilities"):
            for xss_type in ["reflected", "stored", "dom_based"]:
                vulns = [
                    v
                    for v in result["vulnerabilities"]
                    if v.get("xss_type") == xss_type
                ]
                if vulns:
                    console.print(
                        f"\n[bold cyan]{xss_type.upper()} XSS ({len(vulns)}):[/bold cyan]"
                    )
                    for vuln in vulns[:5]:
                        console.print(f"  • Parámetro: {vuln.get('parameter')}")
                        console.print(f"    Payload: {vuln.get('payload', '')[:60]}...")
                        console.print(f"    Severidad: {vuln.get('severity')}")
                        console.print()

    def _display_ssti_results(self, result: dict):
        """Mostrar resultados de SSTI Detector"""
        console.print(
            f"\n[bold]Vulnerable: {'🚨 Sí' if result.get('vulnerable') else '✅ No'}[/bold]"
        )
        console.print(f"[bold]Severidad: {result.get('severity', 'None')}[/bold]")
        console.print(f"[bold]Confianza: {result.get('confidence', 0)}%[/bold]\n")

        if result.get("vulnerabilities"):
            # Agrupar por engine
            engines = {}
            for vuln in result["vulnerabilities"]:
                engine = vuln.get("engine", "unknown")
                if engine not in engines:
                    engines[engine] = []
                engines[engine].append(vuln)

            # Mostrar por engine
            for engine, vulns in engines.items():
                engine_name = vuln.get("subtype", engine.upper())
                console.print(
                    f"\n[bold cyan]{engine_name} ({len(vulns)} vulnerabilidades):[/bold cyan]"
                )

                for vuln in vulns:
                    phase = vuln.get("phase", "detection")
                    phase_badge = (
                        "🔴 RCE" if phase == "exploitation" else "🟡 Detection"
                    )

                    console.print(
                        f"  {phase_badge} [{vuln.get('severity')}] Parámetro: {vuln.get('parameter')}"
                    )
                    console.print(f"     CVSS: {vuln.get('cvss_score', 0)}")
                    console.print(f"     Evidence: {vuln.get('evidence', '')[:80]}")

                    if phase == "exploitation":
                        console.print(f"     [bold red]⚠️  RCE CONFIRMADO[/bold red]")

                    console.print()

            # Resumen
            attack_summary = result.get("attack_summary", {})
            if attack_summary:
                console.print("\n[bold cyan]Attack Flow Summary:[/bold cyan]")
                console.print(f"  Total Steps: {attack_summary.get('total_steps', 0)}")
                console.print(
                    f"  Vulnerable Steps: {attack_summary.get('vulnerable_steps', 0)}"
                )
                engines_detected = attack_summary.get("engines_detected", [])
                console.print(
                    f"  Engines Detected: {', '.join([e.upper() for e in engines_detected])}"
                )

    def _display_csrf_results(self, result: dict):
        """Mostrar resultados de CSRF Tester"""
        console.print(
            f"\n[bold]Vulnerable: {'🚨 Sí' if result.get('vulnerable') else '✅ No'}[/bold]\n"
        )

        protections = result.get("csrf_protections", {})
        console.print("[bold cyan]Protecciones CSRF:[/bold cyan]")
        console.print(
            f"  Token CSRF: {'✓' if protections.get('has_csrf_token') else '✗'}"
        )
        console.print(
            f"  SameSite Cookie: {'✓' if protections.get('samesite_cookie') else '✗'}"
        )
        console.print(f"  Referer Check: {protections.get('referer_check', 'Unknown')}")

        if result.get("vulnerabilities"):
            console.print("\n[red]Problemas Encontrados:[/red]")
            for vuln in result["vulnerabilities"]:
                console.print(f"  [{vuln.get('severity')}] {vuln.get('issue')}")

    def _display_ssh_brute_results(self, result: dict):
        """Mostrar resultados de SSH Brute Force"""
        console.print(f"\n[bold]Intentos: {result.get('total_attempts', 0)}[/bold]")
        console.print(
            f"[bold]Duración: {result.get('duration_seconds', 0):.2f}s[/bold]\n"
        )

        if result.get("successful_logins"):
            console.print(
                "[bold green]✅ CREDENCIALES VÁLIDAS ENCONTRADAS:[/bold green]"
            )
            for cred in result["successful_logins"]:
                console.print(f"  🔓 {cred.get('username')}:{cred.get('password')}")
                if cred.get("banner"):
                    console.print(f"     Banner: {cred.get('banner')[:100]}")
        else:
            console.print("[yellow]No se encontraron credenciales válidas[/yellow]")

        if result.get("blocked"):
            console.print("\n[red]⚠️  POSIBLE BANEO DETECTADO[/red]")

    # === MÉTODOS DE DISPLAY ORIGINALES (SIN CAMBIOS) ===

    def _display_port_scan_results(self, result: dict):
        """Mostrar resultados de port scanner"""
        table = Table(
            title=f"Puertos Abiertos - {result.get('target')}", box=box.ROUNDED
        )
        table.add_column("Puerto", style="cyan", justify="center")
        table.add_column("Servicio", style="green")
        table.add_column("Riesgo", style="magenta")
        table.add_column("Banner", style="yellow")

        for port in result.get("open_ports", []):
            risk_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(port["risk_level"], "⚪")

            banner = port.get("banner", "N/A")
            banner_display = (
                banner[:50] + "..." if banner and len(banner) > 50 else banner or "N/A"
            )

            table.add_row(
                str(port["port"]),
                port["service"],
                f"{risk_emoji} {port['risk_level']}",
                banner_display,
            )

        console.print(table)

        if result.get("recommendations"):
            console.print("\n[bold cyan]Recomendaciones:[/bold cyan]")
            for rec in result["recommendations"]:
                console.print(f"  • {rec}")

    def _display_banner_results(self, result: dict):
        """Mostrar resultados de banner grabber"""
        for r in result.get("results", []):
            panel_content = f"""
[bold]Puerto:[/bold] {r['port']} ({r['service']})
[bold]Server:[/bold] {r['server']} {r['version']}
[bold]Riesgo:[/bold] {r['risk_level']}

[bold]Tecnologías:[/bold] {', '.join(r['technologies']) if r['technologies'] else 'N/A'}

[bold]Banner:[/bold]
{r['banner'][:200] if r['banner'] else 'N/A'}
            """

            if r["vulnerabilities"]:
                panel_content += f"\n[bold red]Vulnerabilidades:[/bold red]\n"
                for vuln in r["vulnerabilities"]:
                    panel_content += f"  • {vuln}\n"

            console.print(
                Panel(panel_content, title=f"Puerto {r['port']}", border_style="cyan")
            )

    def _display_subdomain_results(self, result: dict):
        """Mostrar resultados de subdomain enum"""
        table = Table(title=f"Subdominios - {result.get('domain')}", box=box.ROUNDED)
        table.add_column("Subdominio", style="cyan")
        table.add_column("IPs", style="green")
        table.add_column("HTTP", style="yellow", justify="center")
        table.add_column("HTTPS", style="yellow", justify="center")
        table.add_column("Riesgo", style="magenta")

        for sub in result.get("subdomains", []):
            http_status = "✓" if sub["http_status"]["http"] else "✗"
            https_status = "✓" if sub["http_status"]["https"] else "✗"

            risk_emoji = {"High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                sub["risk_level"], "⚪"
            )

            table.add_row(
                sub["full_domain"],
                ", ".join(sub["ips"][:2]),
                http_status,
                https_status,
                f"{risk_emoji} {sub['risk_level']}",
            )

        console.print(table)
        console.print(
            f"\n[cyan]Total encontrados: {result.get('found_count', 0)}/{result.get('total_tested', 0)}[/cyan]"
        )

    def _display_webdir_results(self, result: dict):
        """Mostrar resultados de web directory scanner"""
        table = Table(
            title=f"Recursos Encontrados - {result.get('target')}", box=box.ROUNDED
        )
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green", justify="center")
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Riesgo", style="magenta")

        for resource in result.get("resources", [])[:20]:
            risk_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(resource["risk_level"], "⚪")

            url_display = (
                resource["url"][-50:] if len(resource["url"]) > 50 else resource["url"]
            )

            table.add_row(
                url_display,
                str(resource["status_code"]),
                f"{resource['size']} bytes",
                f"{risk_emoji} {resource['risk_level']}",
            )

        console.print(table)
        console.print(
            f"\n[cyan]Total encontrados: {result.get('found_count', 0)}[/cyan]"
        )

    def _display_header_results(self, result: dict):
        """Mostrar resultados de header analyzer"""
        console.print(
            f"\n[bold]Security Score: {result.get('security_score', 0)}/100[/bold]"
        )
        console.print(
            f"[bold]Risk Level: {result.get('risk_level', 'Unknown')}[/bold]\n"
        )

        if result.get("security_headers", {}).get("present"):
            console.print("[green]✓ Headers de Seguridad Presentes:[/green]")
            for header in result["security_headers"]["present"]:
                status = "✓" if header["properly_configured"] else "⚠"
                console.print(f"  {status} {header['header']}")

        if result.get("security_headers", {}).get("missing"):
            console.print("\n[red]✗ Headers de Seguridad Faltantes:[/red]")
            for header in result["security_headers"]["missing"]:
                console.print(f"  [{header['risk_level']}] {header['header']}")

    def _display_dns_results(self, result: dict):
        """Mostrar resultados de DNS gatherer"""
        console.print(
            f"\n[bold cyan]DNS Information - {result.get('domain')}[/bold cyan]\n"
        )

        if "A" in result.get("records", {}):
            console.print("[green]Registros A:[/green]")
            for ip in result["records"]["A"]:
                console.print(f"  • {ip}")

        if result.get("nameservers"):
            console.print("\n[green]Nameservers:[/green]")
            for ns in result["nameservers"]:
                console.print(f"  • {ns}")

        if result.get("mail_servers"):
            console.print("\n[green]Mail Servers:[/green]")
            for mx in result["mail_servers"]:
                console.print(f"  [{mx['priority']}] {mx['server']}")

        console.print("\n[cyan]Email Security:[/cyan]")
        console.print(
            f"  SPF: {'✓' if result.get('txt_records', {}).get('spf') else '✗'}"
        )
        console.print(
            f"  DMARC: {'✓' if result.get('txt_records', {}).get('dmarc') else '✗'}"
        )
        console.print(f"  DNSSEC: {'✓' if result.get('dnssec_enabled') else '✗'}")

        if result.get("zone_transfer", {}).get("vulnerable"):
            console.print("\n[red]🔴 CRÍTICO: Zone Transfer Vulnerable![/red]")

    def _display_ssl_results(self, result: dict):
        """Mostrar resultados de SSL analyzer"""
        cert = result.get("certificate", {})

        panel_content = f"""
[bold]Security Score:[/bold] {result.get('security_score', 0)}/100
[bold]Risk Level:[/bold] {result.get('risk_level', 'Unknown')}

[bold cyan]Certificado:[/bold cyan]
  Válido: {'✓' if cert.get('is_valid') else '✗'}
  Emisor: {cert.get('issuer', 'N/A')}
  Sujeto: {cert.get('subject', 'N/A')}
  Expira: {cert.get('not_after', 'N/A')} ({cert.get('days_until_expiry', 0)} días)
  Auto-firmado: {'Sí' if cert.get('is_self_signed') else 'No'}

[bold cyan]Protocolos:[/bold cyan]
  Soportados: {', '.join(result.get('protocols', {}).get('supported', []))}
        """

        console.print(
            Panel(panel_content, title="SSL/TLS Analysis", border_style="cyan")
        )

        if result.get("vulnerabilities"):
            console.print("\n[red]Vulnerabilidades:[/red]")
            for vuln in result["vulnerabilities"]:
                console.print(
                    f"  [{vuln['severity']}] {vuln['name']}: {vuln['description']}"
                )

    def _display_vuln_scan_results(self, result: dict):
        """Mostrar resultados de vulnerability scanner"""
        console.print(
            f"\n[bold]Total Vulnerabilidades: {result.get('total_vulnerabilities', 0)}[/bold]"
        )
        console.print(f"  🔴 Críticas: {result.get('critical_count', 0)}")
        console.print(f"  🟠 Altas: {result.get('high_count', 0)}")
        console.print(f"  🟡 Medias: {result.get('medium_count', 0)}")
        console.print(f"  🟢 Bajas: {result.get('low_count', 0)}")

        for vuln in result.get("vulnerabilities", []):
            severity_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(vuln["severity"], "⚪")

            panel_content = f"""
[bold]CVSS:[/bold] {vuln.get('cvss_score', 'N/A')}/10.0
[bold]CWE:[/bold] {vuln.get('cwe', 'N/A')}

{vuln.get('description', '')}

[bold cyan]Remediación:[/bold cyan]
{vuln.get('remediation', 'N/A')}
            """

            console.print(
                Panel(
                    panel_content,
                    title=f"{severity_emoji} {vuln['title']}",
                    border_style=(
                        "red" if vuln["severity"] in ["Critical", "High"] else "yellow"
                    ),
                )
            )

    def _view_logs(self):
        logs = db_manager.get_logs(self.current_project.id, limit=20)

        if not logs:
            console.print("[yellow]No hay logs para este proyecto[/yellow]")
            return

        table = Table(title=f"Logs - {self.current_project.name}", box=box.ROUNDED)
        table.add_column("Fecha", style="cyan")
        table.add_column("Herramienta", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Estado", style="magenta", justify="center")
        table.add_column("MITRE", style="blue")

        for log in logs:
            status_style = "[green]✓[/green]" if log.success else "[red]✗[/red]"

            table.add_row(
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.tool_name,
                log.target[:30],
                status_style,
                log.mitre_technique_id or "N/A",
            )

        console.print(table)

    def _view_vulnerabilities(self):
        """Ver vulnerabilidades del proyecto"""
        vulns = db_manager.get_vulnerabilities(self.current_project.id)

        if not vulns:
            console.print("[yellow]No hay vulnerabilidades registradas[/yellow]")
            return

        table = Table(
            title=f"Vulnerabilidades - {self.current_project.name}", box=box.ROUNDED
        )
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Título", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("CVSS", style="red", justify="center")
        table.add_column("Severidad", style="magenta", justify="center")
        table.add_column("MITRE", style="blue")

        for vuln in vulns:
            severity_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(vuln.severity, "⚪")

            table.add_row(
                str(vuln.id),
                vuln.title[:50],
                vuln.target[:30],
                f"{vuln.cvss_score:.1f}",
                f"{severity_emoji} {vuln.severity}",
                vuln.mitre_technique_id or "N/A",
            )

        console.print(table)


def run_ssti_detector(project_id: int):
    """SSTI Detector v3.1 - Hybrid Mode"""
    from tools.ssti_detector import SSTIDetector
    import json
    from core.database import db_manager

    console.print("\n[bold red]💉 SSTI DETECTOR v3.1[/bold red]")
    console.print("[yellow]Server-Side Template Injection Detection[/yellow]\n")

    try:
        detector = SSTIDetector(timeout=10.0, mode="auto")

        if detector.sstimap_available:
            console.print("[green]✅ Modo: SSTIMAP[/green]")
        else:
            console.print("[yellow]⚠️  Modo: NATIVO[/yellow]")

        target = Prompt.ask(
            "[cyan]Target URL[/cyan]", default="http://example.com?param=test"
        )

        if "?" not in target:
            console.print("[red]❌ URL debe tener parámetros[/red]")
            return

        deep = Prompt.ask(
            "[cyan]Deep scan?[/cyan]", choices=["yes", "no"], default="no"
        )
        deep_scan = deep == "yes"

        console.print("\n[bold green]🚀 Escaneando...[/bold green]\n")

        result = detector.scan(target, deep_scan=deep_scan)

        console.print(f"\n{'='*70}")
        console.print("[bold]RESULTADOS[/bold]")
        console.print(f"{'='*70}\n")

        if result["vulnerable"]:
            console.print("[bold red]🚨 VULNERABLE[/bold red]")
        else:
            console.print("[bold green]✅ SEGURO[/bold green]")

        console.print(f"Modo: [cyan]{result.get('mode', 'unknown').upper()}[/cyan]")
        console.print(
            f"Duration: [yellow]{result.get('scan_duration', 0):.1f}s[/yellow]"
        )
        console.print(f"Severity: [red]{result.get('severity')}[/red]")

        if result["vulnerabilities"]:
            console.print(
                f"\n[yellow]📋 Vulnerabilidades: {len(result['vulnerabilities'])}[/yellow]\n"
            )

            for i, vuln in enumerate(result["vulnerabilities"], 1):
                console.print(f"[bold]{i}. {vuln['subtype']}[/bold]")
                console.print(f"   CVSS: [red]{vuln['cvss_score']}[/red]")

        console.print("[cyan]💾 Guardando...[/cyan]")

        log = db_manager.create_log(
            project_id=project_id,
            tool_name=f'SSTI Detector v3.1 ({result.get("mode")})',
            tool_category="OWASP Top 10",
            target=target,
            command=f"ssti_scan {target}",
            output=json.dumps(result),
            success=True,
            duration_seconds=result.get("scan_duration", 0),
        )

        console.print(f"[green]✅ Log: ID {log.id}[/green]")

        if result["vulnerabilities"]:
            for vuln in result["vulnerabilities"]:
                db_manager.create_vulnerability(
                    project_id=project_id,
                    title=f"SSTI: {vuln['subtype']}",
                    description=f"Param: {vuln['parameter']}\nEvidence: {vuln['evidence']}",
                    target=vuln["url"],
                    cvss_score=vuln["cvss_score"],
                    severity=vuln["severity"],
                    cwe_id=vuln["cwe_id"],
                    mitre_technique_id=vuln.get("mitre_technique_id"),
                    proof_of_concept=vuln.get("payload", "Auto"),
                    remediation=vuln["remediation"],
                )
            console.print("[green]✅ Vulnerabilidades guardadas[/green]")

        console.print(f"\n[cyan]📊 Dashboard: Tab 3 → SSTI → Log {log.id}[/cyan]\n")

    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/red]")


def run_reflection_analyzer(project_id: int, target: str = None):
    """Reflection Analyzer - Detecta payload reflection"""
    from tools.reflection_analyzer import ReflectionAnalyzer
    import json
    from core.database import db_manager
    from urllib.parse import urlparse, parse_qs

    console.print("\n[bold cyan]🔍 REFLECTION ANALYZER v1.0[/bold cyan]")
    console.print("[yellow]Analizando payload reflection...[/yellow]\n")

    try:
        if not target:
            console.print("[red]❌ Target requerido[/red]")
            return

        if "?" not in target:
            console.print("[red]❌ URL debe tener parámetros (ej: ?name=test)[/red]")
            return

        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        if not params:
            console.print("[red]❌ No se detectaron parámetros[/red]")
            return

        param = list(params.keys())[0]

        console.print(f"[cyan]Target: {target}[/cyan]")
        console.print(f"[cyan]Parameter: {param}[/cyan]\n")
        # Progreso mostrado por el scanner en tiempo real

        analyzer = ReflectionAnalyzer(timeout=10.0)
        result = analyzer.scan(target, parameter=param)

        console.print(f"\n{'='*70}")
        console.print("[bold]RESULTADOS[/bold]")
        console.print(f"{'='*70}\n")

        if result["vulnerable"]:
            console.print("[bold red]🚨 VULNERABLE[/bold red]")
        else:
            console.print("[bold green]✅ NO VULNERABLE[/bold green]")

        console.print(
            f"Vulnerabilities: [yellow]{result['vulnerability_count']}[/yellow]"
        )
        console.print(f"Severity: [red]{result['severity']}[/red]")
        console.print(f"Duration: {result.get('scan_duration', 0):.1f}s")

        if result["vulnerabilities"]:
            console.print(f"\n[yellow]📋 Detalle:[/yellow]\n")
            for i, v in enumerate(result["vulnerabilities"], 1):
                console.print(f"{i}. {v['subtype']}")
                console.print(f"   Context: {v['context']}")
                console.print(f"   CVSS: {v['cvss_score']}")

        console.print(f"\n[cyan]💾 Guardando...[/cyan]")

        log = db_manager.create_log(
            project_id=project_id,
            tool_name="Reflection Analyzer v1.0",
            tool_category="OWASP Top 10",
            target=target,
            command=f"reflection_analyzer {target}",
            output=json.dumps(result),
            success=True,
            duration_seconds=result.get("scan_duration", 0),
        )

        console.print(f"[green]✅ Log ID: {log.id}[/green]")

        if result["vulnerabilities"]:
            for vuln in result["vulnerabilities"]:
                db_manager.create_vulnerability(
                    project_id=project_id,
                    title=f"Reflection: {vuln['subtype']}",
                    description=f"Context: {vuln['context']}\nPayload: {vuln['payload']}\nEvidence: {vuln['evidence']}",
                    target=vuln["url"],
                    cvss_score=vuln["cvss_score"],
                    severity=vuln["severity"],
                    cwe_id=vuln["cwe_id"],
                    mitre_technique_id=vuln.get("mitre_technique_id"),
                    mitre_technique_name=vuln.get("mitre_technique_name"),
                    mitre_tactic=vuln.get("mitre_tactic"),
                    proof_of_concept=vuln["payload"],
                    remediation=vuln["remediation"],
                )
            console.print(
                f"[green]✅ {len(result['vulnerabilities'])} vulnerabilidades guardadas[/green]"
            )

        console.print(f"\n{'='*70}\n")

    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        import traceback

        console.print(f"[dim]{traceback.format_exc()}[/dim]")


def run_lfi_rfi_scanner(project_id: int, target: str = None):
    """LFI/RFI Scanner v2.4 - Solo 1 log"""
    import json
    import time
    import traceback
    from core.database import db_manager
    from urllib.parse import urlparse, parse_qs

    console.print("\n[bold cyan]🗂️  LFI/RFI SCANNER v2.4[/bold cyan]")
    console.print("[yellow]Local/Remote File Inclusion Detection[/yellow]\n")

    try:
        if not target:
            console.print("[red]❌ Target requerido[/red]")
            return

        console.print(f"[cyan]🎯 Target: {target}[/cyan]")

        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        if params:
            param = list(params.keys())[0]
            console.print(f"[cyan]📌 Parameter: {param}[/cyan]\n")
        else:
            console.print(f"[yellow]⚡ Auto-scan mode[/yellow]\n")

        from tools.lfi_rfi_scanner import LFIRFIScanner

        scanner = LFIRFIScanner(timeout=10.0)

        console.print("[bold green]🚀 INICIANDO SCAN...[/bold green]\n")

        result = scanner.scan(target, parameter=None, scan_rfi=True)

        console.print(f"\n{'='*70}")
        console.print("[bold]RESULTADOS[/bold]")
        console.print(f"{'='*70}\n")

        if result["vulnerable"]:
            console.print("[bold red]🚨 VULNERABLE[/bold red]")
        else:
            console.print("[bold green]✅ NO VULNERABLE[/bold green]")

        console.print(
            f"Vulnerabilities: [yellow]{result['vulnerability_count']}[/yellow]"
        )
        console.print(f"Severity: [red]{result['severity']}[/red]")
        console.print(f"Duration: {result.get('scan_duration', 0):.1f}s")
        console.print(f"Requests: {result.get('total_requests', 0)}")

        if result.get("auto_scan"):
            console.print(
                f"[cyan]Mode: Auto-scan ({len(result.get('parameters_tested', []))} parameters)[/cyan]"
            )

        if result["vulnerabilities"]:
            console.print(f"\n[yellow]📋 Vulnerabilidades:[/yellow]\n")
            for i, v in enumerate(result["vulnerabilities"], 1):
                console.print(f"{i}. {v['type']}")
                console.print(f"   Parameter: {v['parameter']}")
                console.print(f"   CVSS: {v['cvss_score']}")

        console.print(f"\n[cyan]💾 Guardando...[/cyan]")

        # ===== ÚNICO LOG =====
        log = db_manager.create_log(
            project_id=project_id,
            tool_name="LFI/RFI Scanner",
            tool_category="OWASP Top 10",
            target=target,
            command=f"lfi_rfi_scanner {target}",
            output=json.dumps(result),
            success=True,
            duration_seconds=result.get("scan_duration", 0),
        )

        console.print(f"[green]✅ Log guardado (ID: {log.id})[/green]")

        if result["vulnerabilities"]:
            for vuln in result["vulnerabilities"]:
                db_manager.create_vulnerability(
                    project_id=project_id,
                    title=vuln["type"],
                    description=f"Parameter: {vuln['parameter']}\nPayload: {vuln['payload']}",
                    target=vuln["url"],
                    cvss_score=vuln["cvss_score"],
                    severity=vuln["severity"],
                    cwe_id=vuln["cwe_id"],
                    mitre_technique_id=vuln.get("mitre_technique_id"),
                    proof_of_concept=vuln.get("proof_of_concept"),
                    remediation=vuln.get("remediation"),
                )
            console.print(
                f"[green]✅ {len(result['vulnerabilities'])} vulnerabilidades guardadas[/green]"
            )

        console.print(f"\n{'='*70}\n")

    except Exception as e:
        console.print(f"\n[bold red]❌ ERROR:[/bold red]")
        console.print(f"[red]{str(e)}[/red]")
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main():
    try:
        cli = BerebrumCLI()
        cli.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Programa interrumpido[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error fatal: {e}[/red]")
        import traceback

        console.print(traceback.format_exc())
        sys.exit(1)




def run_command_injection_tester(project):
    """Ejecuta Command Injection Tester"""
    print("\n" + "="*60)
    print("COMMAND INJECTION TESTER")
    print("="*60)
    
    target = input("\nTarget URL: ").strip()
    if not target:
        print("❌ URL requerida")
        return
    
    # Agregar http:// si falta
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    parameter = input("Parámetro específico (Enter para auto-detección): ").strip()
    if not parameter:
        parameter = None
    
    print(f"\n[*] Escaneando: {target}")
    if parameter:
        print(f"[*] Parámetro: {parameter}")
    else:
        print(f"[*] Modo: Auto-detección")
    
    print("\n" + "-"*60)
    
    try:
        result = scan_command_injection(
            url=target,
            parameter=parameter,
            timeout=10.0
        )
        
        print("\n" + "="*60)
        print("RESULTADOS")
        print("="*60)
        
        vulnerable = result.get('vulnerable', False)
        severity = result.get('severity', 'None')
        confidence = result.get('confidence', 0)
        vuln_count = result.get('vulnerability_count', 0)
        
        if vulnerable:
            print(f"\n🚨 VULNERABLE A COMMAND INJECTION")
            print(f"   Severidad: {severity}")
            print(f"   Confianza: {confidence}%")
            print(f"   Vulnerabilidades: {vuln_count}")
            
            vulns = result.get('vulnerabilities', [])
            for i, vuln in enumerate(vulns, 1):
                print(f"\n   [{i}] {vuln.get('type', 'Command Injection')}")
                print(f"       Parámetro: {vuln.get('parameter')}")
                print(f"       Payload: {vuln.get('payload')}")
                print(f"       CVSS: {vuln.get('cvss_score')}")
                print(f"       Evidencia: {vuln.get('evidence', 'N/A')[:80]}...")
        else:
            print(f"\n✅ NO VULNERABLE")
            print(f"   Severidad: {severity}")
            print(f"   Confianza: {confidence}%")
        
        # Stats
        duration = result.get('scan_duration', 0)
        total_req = result.get('total_requests', 0)
        
        print(f"\n📊 Estadísticas:")
        print(f"   Duración: {duration:.2f}s")
        print(f"   Requests: {total_req}")
        
        params_tested = result.get('parameters_tested', [])
        if params_tested:
            print(f"   Parámetros probados: {len(params_tested)}")
        
        # Guardar log
        print(f"\n💾 Guardando log...")
        
        log_id = create_log(
            project_id=project.id,
            tool_name='Command Injection Tester',
            tool_category='OWASP Top 10',
            target=target,
            output=result,
            success=True,
            duration_seconds=duration
        )
        
        if log_id:
            print(f"✅ Log guardado (ID: {log_id})")
        
        # Guardar vulnerabilidades
        if vulnerable:
            print(f"\n💾 Guardando vulnerabilidades...")
            
            for vuln in result.get('vulnerabilities', []):
                vuln_id = create_vulnerability(
                    project_id=project.id,
                    log_id=log_id,
                    title=f"Command Injection - {vuln.get('parameter')}",
                    severity=vuln.get('severity', 'Critical'),
                    cvss_score=vuln.get('cvss_score', 9.8),
                    cwe_id=vuln.get('cwe_id', 'CWE-78'),
                    description=f"Command Injection vulnerability in parameter '{vuln.get('parameter')}'",
                    target=target,
                    proof_of_concept=vuln.get('proof_of_concept', ''),
                    remediation=vuln.get('remediation', ''),
                    mitre_technique_id=vuln.get('mitre_technique_id'),
                    mitre_technique_name=vuln.get('mitre_technique_name'),
                    mitre_tactic=vuln.get('mitre_tactic')
                )
                
                if vuln_id:
                    print(f"✅ Vulnerabilidad guardada (ID: {vuln_id})")
        
        print("\n" + "="*60)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Escaneo interrumpido por el usuario")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        
        # Guardar log de error
        create_log(
            project_id=project.id,
            tool_name='Command Injection Tester',
            tool_category='OWASP Top 10',
            target=target,
            output={'error': str(e)},
            success=False,
            duration_seconds=0
        )
    
    input("\nPresiona Enter para continuar...")


if __name__ == "__main__":
    main()
