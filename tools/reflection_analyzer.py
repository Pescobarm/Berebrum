"""
Reflection Analyzer v2.0
Detecta payload reflection en contextos peligrosos
Creado desde cero - Sin errores de sintaxis
"""

import re
import requests
import urllib3

# Suprimir warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class ReflectionAnalyzer:
    """
    Analiza reflection de payloads en diferentes contextos
    v2.0 - Búsqueda global mejorada
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Payloads optimizados para detección
        self.payloads = [
            {
                "name": "Unique ID",
                "value": "REFLECT123TEST456UNIQUE",
                "type": "detection",
            },
            {"name": "HTML Tag", "value": "<script>alert(1)</script>", "type": "xss"},
            {"name": "JS Break", "value": '"}};alert(1);//', "type": "xss"},
            {"name": "Template Syntax", "value": "{{__globals__}}", "type": "template"},
            {
                "name": "XSS Vector",
                "value": "'>\"><img src=x onerror=alert(1)>",
                "type": "xss",
            },
            {"name": "Math Test", "value": "{{7*7}}", "type": "template"},
        ]

    def scan(self, url: str, parameter: str) -> Dict:
        """
        Escanea un parámetro específico buscando reflection
        """
        print(f"[*] Reflection Analyzer v2.0")
        print(f"[*] Target: {url}")
        print(f"[*] Parámetros a probar: {parameter}")

        start_time = time.time()
        vulnerabilities = []
        total_requests = 0

        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if parameter not in params:
            params[parameter] = [""]

        # Test cada payload
        for payload_info in self.payloads:
            payload = payload_info["value"]
            payload_name = payload_info["name"]

            print(f"[*] Testing parameter: {parameter}")
            print(f"  [*] {payload_name}: {payload[:30]}...")

            # Construir URL con payload
            test_params = params.copy()
            test_params[parameter] = [payload]

            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )

            try:
                # Hacer request
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                total_requests += 1

                # Verificar si el payload se refleja
                if payload in response.text:
                    print(f"  [✓] Reflected")

                    # Analizar contexto
                    contexts = self._analyze_context_v2(response.text, payload)

                    dangerous_contexts = [c for c in contexts if c["dangerous"]]

                    if dangerous_contexts:
                        print(f"  [!] Dangerous contexts: {len(dangerous_contexts)}")
                        for ctx in dangerous_contexts:
                            print(f"      → {ctx['type']}")

                        # Crear vulnerabilidad por cada contexto peligroso
                        for ctx in dangerous_contexts:
                            vuln = self._create_vulnerability(
                                url=test_url,
                                parameter=parameter,
                                payload=payload,
                                payload_type=payload_info["type"],
                                context=ctx,
                            )
                            vulnerabilities.append(vuln)
                    else:
                        print(f"  [i] Reflected in safe context")
                else:
                    print(f"  [✗] Not reflected")

            except Exception as e:
                print(f"  [!] Error: {e}")
                continue

        duration = time.time() - start_time

        # Generar resultado
        result = {
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity": self._calculate_severity(vulnerabilities),
            "confidence": self._calculate_confidence(vulnerabilities),
            "scan_duration": duration,
            "total_requests": total_requests,
            "target": url,
            "parameter": parameter,
        }

        return result

    def _analyze_context_v2(self, body: str, payload: str) -> List[Dict]:
        """
        Analiza contexto LOCAL + GLOBAL
        v2.0 - Búsqueda mejorada sin errores de sintaxis
        """
        contexts = []
        escaped = re.escape(payload)

        # Buscar todas las ocurrencias
        matches = list(re.finditer(escaped, body))

        if not matches:
            return contexts

        for match in matches:
            pos = match.start()

            # Contexto LOCAL (400 chars)
            start = max(0, pos - 200)
            end = min(len(body), pos + len(payload) + 200)
            snippet = body[start:end]

            context = {
                "snippet": snippet[:100],  # Limitar snippet
                "type": "Unknown",
                "dangerous": False,
            }

            # === ANÁLISIS LOCAL ===

            # 1. JavaScript Config Object (drupalSettings, etc)
            if self._has_js_config(snippet):
                context["type"] = "JavaScript Config Object"
                context["dangerous"] = True

            # 2. Script tag
            elif "<script" in snippet.lower():
                context["type"] = "Script Tag"
                context["dangerous"] = True

            # 3. JavaScript Variable
            elif self._has_js_variable(snippet):
                context["type"] = "JavaScript Variable"
                context["dangerous"] = True

            # 4. HTML Attribute
            elif self._has_html_attribute(snippet):
                context["type"] = "HTML Attribute"
                context["dangerous"] = True

            # 5. HTML Tag Content
            elif self._has_html_tag(snippet):
                context["type"] = "HTML Tag Content"
                context["dangerous"] = False

            # 6. JSON Data
            elif self._has_json(snippet):
                context["type"] = "JSON Data"
                context["dangerous"] = False

            # 7. Comment
            elif self._is_comment(snippet):
                context["type"] = "Comment"
                context["dangerous"] = False

            # === ANÁLISIS GLOBAL ===
            # Si no se detectó peligro localmente, buscar globalmente

            if not context["dangerous"]:
                # Buscar drupalSettings en TODO el body
                if "drupalSettings" in body:
                    # Verificar que payload está en un objeto
                    if self._payload_in_js_object(body, payload):
                        context["type"] = "JavaScript Config Object"
                        context["dangerous"] = True

                # Buscar window.* configs
                elif "window." in body:
                    if self._payload_in_window_config(body, payload):
                        context["type"] = "JavaScript Config Object"
                        context["dangerous"] = True

            # Solo agregar si es relevante
            if context["type"] != "Unknown" or context["dangerous"]:
                contexts.append(context)

        return contexts

    def _has_js_config(self, text: str) -> bool:
        """Detecta JavaScript config objects"""
        patterns = [
            r"drupalSettings\s*=",
            r"settings\s*=\s*\{",
            r"config\s*=\s*\{",
            r"window\.\w+\s*=",
        ]
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)

    def _has_js_variable(self, text: str) -> bool:
        """Detecta variables JavaScript"""
        return bool(re.search(r"var\s+\w+\s*=", text, re.IGNORECASE))

    def _has_html_attribute(self, text: str) -> bool:
        """Detecta atributos HTML"""
        return bool(re.search(r"<\w+[^>]*\s+\w+=", text))

    def _has_html_tag(self, text: str) -> bool:
        """Detecta contenido de tags HTML"""
        return bool(re.search(r"<\w+[^>]*>.*?</\w+>", text))

    def _has_json(self, text: str) -> bool:
        """Detecta JSON data"""
        return bool(re.search(r'\{[^}]*"[^"]*":', text))

    def _is_comment(self, text: str) -> bool:
        """Detecta comentarios"""
        return "<!--" in text or "//" in text or "/*" in text

    def _payload_in_js_object(self, body: str, payload: str) -> bool:
        """Verifica si payload está dentro de un objeto JS"""
        escaped = re.escape(payload)
        # Buscar payload entre llaves
        pattern = r"\{[^}]*" + escaped
        return bool(re.search(pattern, body, re.DOTALL))

    def _payload_in_window_config(self, body: str, payload: str) -> bool:
        """Verifica si payload está en window.* config"""
        escaped = re.escape(payload)
        pattern = r"window\.\w+.*?" + escaped
        return bool(re.search(pattern, body, re.DOTALL))

    def _create_vulnerability(
        self, url: str, parameter: str, payload: str, payload_type: str, context: Dict
    ) -> Dict:
        """Crea objeto de vulnerabilidad"""

        # Calcular CVSS según contexto y tipo de payload
        cvss = self._calculate_cvss(context["type"], payload_type)

        # Mapeo de CWE
        cwe_map = {
            "JavaScript Config Object": "CWE-200",
            "JavaScript Variable": "CWE-200",
            "Script Tag": "CWE-79",
            "HTML Attribute": "CWE-79",
            "HTML Tag Content": "CWE-79",
            "JSON Data": "CWE-200",
        }

        cwe_id = cwe_map.get(context["type"], "CWE-200")

        # Severidad
        if cvss >= 9.0:
            severity = "Critical"
        elif cvss >= 7.0:
            severity = "High"
        elif cvss >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "payload_type": payload_type,
            "context": context["type"],
            "cvss_score": cvss,
            "severity": severity,
            "cwe_id": cwe_id,
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
            "mitre_tactic": "Initial Access",
            "subtype": f'Reflection in {context["type"]}',
            "evidence": context["snippet"],
            "remediation": self._get_remediation(context["type"]),
        }

    def _calculate_cvss(self, context_type: str, payload_type: str) -> float:
        """Calcula CVSS según contexto y tipo de payload"""
        base_scores = {
            "JavaScript Config Object": 6.5,
            "JavaScript Variable": 6.5,
            "Script Tag": 8.0,
            "HTML Attribute": 7.0,
            "HTML Tag Content": 4.0,
            "JSON Data": 4.0,
            "Comment": 2.0,
        }

        base = base_scores.get(context_type, 5.0)

        # Aumentar si el payload es XSS
        if payload_type == "xss" and context_type in [
            "JavaScript Config Object",
            "JavaScript Variable",
        ]:
            base += 2.0

        return min(base, 10.0)

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

    def _calculate_confidence(self, vulnerabilities: List[Dict]) -> int:
        """Calcula confianza de la detección"""
        if not vulnerabilities:
            return 0

        # Confianza alta si hay múltiples contextos peligrosos
        dangerous_count = sum(1 for v in vulnerabilities if v["cvss_score"] >= 6.0)

        if dangerous_count >= 3:
            return 95
        elif dangerous_count >= 2:
            return 90
        elif dangerous_count >= 1:
            return 85
        else:
            return 75

    def _get_remediation(self, context_type: str) -> str:
        """Obtiene recomendación de remediación"""
        remediations = {
            "JavaScript Config Object": "Encode output before including in JavaScript configs. Use JSON.stringify() with proper escaping.",
            "JavaScript Variable": "Sanitize and encode data before assigning to JavaScript variables.",
            "Script Tag": "Never include user input directly in script tags. Use proper encoding and CSP.",
            "HTML Attribute": "HTML-encode all user input in attributes. Use context-aware encoding.",
            "HTML Tag Content": "HTML-encode user input. Use template engines with auto-escaping.",
            "JSON Data": "Validate and encode JSON data. Use proper JSON encoding functions.",
        }
        return remediations.get(context_type, "Sanitize and encode all user input.")


# Función de compatibilidad para Berebrum
def analyze_reflection(url: str, parameter: str = None, timeout: float = 10.0) -> Dict:
    """
    Función wrapper para compatibilidad con Berebrum
    """
    analyzer = ReflectionAnalyzer(timeout=timeout)

    if not parameter:
        # Extraer parámetro de la URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            parameter = list(params.keys())[0]
        else:
            return {"vulnerable": False, "error": "No parameters found in URL"}

    return analyzer.scan(url, parameter)
