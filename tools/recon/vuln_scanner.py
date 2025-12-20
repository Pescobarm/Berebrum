"""
Berebrum - Basic Vulnerability Scanner
Escáner básico de vulnerabilidades combinando múltiples técnicas
"""

import requests
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import re
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnerabilityScanner:
    """
    Escáner básico de vulnerabilidades comunes
    """
    
    def __init__(self, timeout: float = 10.0):
        """
        Inicializar escáner
        
        Args:
            timeout: Timeout para operaciones
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Berebrum Vulnerability Scanner)'
        })
        self.session.verify = False
    
    def scan(self, target: str) -> Dict[str, any]:
        """
        Escanear target en busca de vulnerabilidades
        
        Args:
            target: URL o IP a escanear
            
        Returns:
            Resultados del escaneo
        """
        vulnerabilities = []
        
        # Determinar si es web o IP
        is_web_target = target.startswith('http')
        
        if is_web_target:
            # Escaneos web
            vulnerabilities.extend(self._check_web_vulnerabilities(target))
        else:
            # Escaneos de red
            vulnerabilities.extend(self._check_network_vulnerabilities(target))
        
        # Clasificar por severidad
        critical = [v for v in vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in vulnerabilities if v['severity'] == 'High']
        medium = [v for v in vulnerabilities if v['severity'] == 'Medium']
        low = [v for v in vulnerabilities if v['severity'] == 'Low']
        
        # Calcular CVSS promedio
        cvss_scores = [v.get('cvss_score', 0) for v in vulnerabilities if 'cvss_score' in v]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        
        return {
            'target': target,
            'scan_type': 'web' if is_web_target else 'network',
            'total_vulnerabilities': len(vulnerabilities),
            'critical_count': len(critical),
            'high_count': len(high),
            'medium_count': len(medium),
            'low_count': len(low),
            'average_cvss': round(avg_cvss, 1),
            'vulnerabilities': vulnerabilities,
            'recommendations': self._generate_recommendations(vulnerabilities),
            'timestamp': datetime.now().isoformat()
        }
    
    def _check_web_vulnerabilities(self, url: str) -> List[Dict]:
        """
        Verificar vulnerabilidades web comunes
        """
        vulnerabilities = []
        
        # 1. SQL Injection básico
        sqli_vulns = self._check_sql_injection(url)
        vulnerabilities.extend(sqli_vulns)
        
        # 2. XSS básico
        xss_vulns = self._check_xss(url)
        vulnerabilities.extend(xss_vulns)
        
        # 3. Path Traversal
        traversal_vulns = self._check_path_traversal(url)
        vulnerabilities.extend(traversal_vulns)
        
        # 4. Open Redirect
        redirect_vulns = self._check_open_redirect(url)
        vulnerabilities.extend(redirect_vulns)
        
        # 5. Security Headers
        header_vulns = self._check_security_headers(url)
        vulnerabilities.extend(header_vulns)
        
        # 6. Information Disclosure
        info_vulns = self._check_information_disclosure(url)
        vulnerabilities.extend(info_vulns)
        
        # 7. Default Credentials
        cred_vulns = self._check_default_credentials(url)
        vulnerabilities.extend(cred_vulns)
        
        return vulnerabilities
    
    def _check_sql_injection(self, url: str) -> List[Dict]:
        """
        Verificación básica de SQL Injection
        """
        vulnerabilities = []
        
        # Payloads de prueba básicos
        payloads = ["'", "1' OR '1'='1", "admin'--", "' OR 1=1--"]
        error_patterns = [
            'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
            'syntax error', 'unexpected', 'warning', 'error in your sql'
        ]
        
        for payload in payloads:
            try:
                # Probar en parámetro de query
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Buscar indicadores de error SQL
                for pattern in error_patterns:
                    if pattern in response.text.lower():
                        vulnerabilities.append({
                            'title': 'Potential SQL Injection',
                            'severity': 'Critical',
                            'cvss_score': 9.8,
                            'description': f'Posible SQL Injection detectada con payload: {payload}',
                            'affected_url': test_url,
                            'evidence': f'Error pattern found: {pattern}',
                            'cwe': 'CWE-89',
                            'remediation': 'Usar consultas parametrizadas o prepared statements. '
                                          'Nunca concatenar entrada de usuario en queries SQL.'
                        })
                        break  # Solo reportar una vez por payload
                
            except:
                pass
        
        return vulnerabilities
    
    def _check_xss(self, url: str) -> List[Dict]:
        """
        Verificación básica de XSS
        """
        vulnerabilities = []
        
        # Payload de prueba básico
        payload = '<script>alert("XSS")</script>'
        
        try:
            test_url = f"{url}?q={payload}"
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Verificar si el payload se refleja sin sanitizar
            if payload in response.text:
                vulnerabilities.append({
                    'title': 'Reflected XSS Vulnerability',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': 'Entrada de usuario se refleja sin sanitización',
                    'affected_url': test_url,
                    'evidence': 'Payload reflejado sin escape',
                    'cwe': 'CWE-79',
                    'remediation': 'Sanitizar y escapar toda entrada de usuario. '
                                  'Implementar Content-Security-Policy.'
                })
        except:
            pass
        
        return vulnerabilities
    
    def _check_path_traversal(self, url: str) -> List[Dict]:
        """
        Verificación de Path Traversal
        """
        vulnerabilities = []
        
        # Payloads de path traversal
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini']
        indicators = ['root:', '[fonts]', '[extensions]']
        
        for payload in payloads:
            try:
                test_url = f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                for indicator in indicators:
                    if indicator in response.text.lower():
                        vulnerabilities.append({
                            'title': 'Path Traversal Vulnerability',
                            'severity': 'High',
                            'cvss_score': 7.5,
                            'description': 'Posible lectura de archivos del sistema',
                            'affected_url': test_url,
                            'evidence': f'Indicator found: {indicator}',
                            'cwe': 'CWE-22',
                            'remediation': 'Validar y sanitizar nombres de archivo. '
                                          'Usar whitelist de archivos permitidos.'
                        })
                        break
            except:
                pass
        
        return vulnerabilities
    
    def _check_open_redirect(self, url: str) -> List[Dict]:
        """
        Verificación de Open Redirect
        """
        vulnerabilities = []
        
        malicious_url = 'http://evil.com'
        
        try:
            test_url = f"{url}?redirect={malicious_url}"
            response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if malicious_url in location:
                    vulnerabilities.append({
                        'title': 'Open Redirect Vulnerability',
                        'severity': 'Medium',
                        'cvss_score': 5.3,
                        'description': 'Redirección a URL externa sin validación',
                        'affected_url': test_url,
                        'evidence': f'Redirects to: {location}',
                        'cwe': 'CWE-601',
                        'remediation': 'Validar URLs de redirección con whitelist. '
                                      'No usar parámetros de usuario directamente.'
                    })
        except:
            pass
        
        return vulnerabilities
    
    def _check_security_headers(self, url: str) -> List[Dict]:
        """
        Verificar headers de seguridad faltantes
        """
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            # Headers críticos faltantes
            if 'Strict-Transport-Security' not in headers:
                vulnerabilities.append({
                    'title': 'Missing HSTS Header',
                    'severity': 'Medium',
                    'cvss_score': 5.3,
                    'description': 'Falta header Strict-Transport-Security',
                    'affected_url': url,
                    'cwe': 'CWE-319',
                    'remediation': 'Agregar header: Strict-Transport-Security: max-age=31536000'
                })
            
            if 'Content-Security-Policy' not in headers:
                vulnerabilities.append({
                    'title': 'Missing CSP Header',
                    'severity': 'Medium',
                    'cvss_score': 5.3,
                    'description': 'Falta header Content-Security-Policy',
                    'affected_url': url,
                    'cwe': 'CWE-79',
                    'remediation': 'Implementar política Content-Security-Policy restrictiva'
                })
            
            if 'X-Frame-Options' not in headers:
                vulnerabilities.append({
                    'title': 'Missing X-Frame-Options',
                    'severity': 'Low',
                    'cvss_score': 4.3,
                    'description': 'Falta protección contra clickjacking',
                    'affected_url': url,
                    'cwe': 'CWE-1021',
                    'remediation': 'Agregar header: X-Frame-Options: DENY'
                })
        except:
            pass
        
        return vulnerabilities
    
    def _check_information_disclosure(self, url: str) -> List[Dict]:
        """
        Verificar divulgación de información
        """
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Server header revelando versión
            server = response.headers.get('Server', '')
            if server and any(v in server for v in ['Apache', 'nginx', 'IIS', 'Microsoft']):
                vulnerabilities.append({
                    'title': 'Server Version Disclosure',
                    'severity': 'Low',
                    'cvss_score': 3.0,
                    'description': f'Header Server revela información: {server}',
                    'affected_url': url,
                    'cwe': 'CWE-200',
                    'remediation': 'Ocultar versión del servidor en configuración'
                })
            
            # X-Powered-By revelando tecnología
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                vulnerabilities.append({
                    'title': 'Technology Stack Disclosure',
                    'severity': 'Low',
                    'cvss_score': 3.0,
                    'description': f'Header X-Powered-By revela: {powered_by}',
                    'affected_url': url,
                    'cwe': 'CWE-200',
                    'remediation': 'Eliminar header X-Powered-By'
                })
            
            # Errores PHP/ASP en página
            error_patterns = ['Fatal error', 'Warning:', 'Notice:', 'Parse error', 'Stack trace']
            for pattern in error_patterns:
                if pattern in response.text:
                    vulnerabilities.append({
                        'title': 'Error Message Disclosure',
                        'severity': 'Medium',
                        'cvss_score': 4.3,
                        'description': f'Mensajes de error visibles: {pattern}',
                        'affected_url': url,
                        'cwe': 'CWE-209',
                        'remediation': 'Deshabilitar display_errors en producción'
                    })
                    break
        except:
            pass
        
        return vulnerabilities
    
    def _check_default_credentials(self, url: str) -> List[Dict]:
        """
        Verificar credenciales por defecto
        """
        vulnerabilities = []
        
        # Credenciales comunes
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('administrator', 'administrator')
        ]
        
        # Endpoints administrativos comunes
        admin_paths = ['/admin', '/login', '/administrator', '/wp-admin']
        
        for path in admin_paths:
            admin_url = f"{url.rstrip('/')}{path}"
            
            for username, password in default_creds:
                try:
                    response = self.session.post(
                        admin_url,
                        data={'username': username, 'password': password},
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    # Verificar si login fue exitoso
                    if response.status_code in [200, 302] and 'dashboard' in response.text.lower():
                        vulnerabilities.append({
                            'title': 'Default Credentials',
                            'severity': 'Critical',
                            'cvss_score': 9.8,
                            'description': f'Credenciales por defecto funcionan: {username}/{password}',
                            'affected_url': admin_url,
                            'cwe': 'CWE-798',
                            'remediation': 'Cambiar credenciales por defecto inmediatamente'
                        })
                        break
                except:
                    pass
        
        return vulnerabilities
    
    def _check_network_vulnerabilities(self, target: str) -> List[Dict]:
        """
        Verificar vulnerabilidades de red
        """
        vulnerabilities = []
        
        # 1. Puertos peligrosos abiertos
        dangerous_ports = {
            23: ('Telnet', 'Critical', 'Puerto Telnet sin cifrado expuesto'),
            21: ('FTP', 'High', 'Puerto FTP expuesto'),
            3389: ('RDP', 'High', 'Puerto RDP expuesto sin restricciones'),
            445: ('SMB', 'High', 'Puerto SMB expuesto (vulnera WannaCry)'),
            1433: ('MSSQL', 'High', 'Puerto SQL Server expuesto'),
            3306: ('MySQL', 'High', 'Puerto MySQL expuesto'),
            5432: ('PostgreSQL', 'High', 'Puerto PostgreSQL expuesto'),
            6379: ('Redis', 'High', 'Puerto Redis expuesto sin auth'),
            27017: ('MongoDB', 'High', 'Puerto MongoDB expuesto')
        }
        
        for port, (service, severity, description) in dangerous_ports.items():
            if self._check_port_open(target, port):
                vulnerabilities.append({
                    'title': f'{service} Port Exposed',
                    'severity': severity,
                    'cvss_score': 9.8 if severity == 'Critical' else 7.5,
                    'description': description,
                    'affected_target': f'{target}:{port}',
                    'cwe': 'CWE-200',
                    'remediation': f'Cerrar puerto {port} o restringir acceso por firewall'
                })
        
        return vulnerabilities
    
    def _check_port_open(self, host: str, port: int) -> bool:
        """
        Verificar si un puerto está abierto
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Generar recomendaciones basadas en vulnerabilidades encontradas
        """
        recommendations = []
        
        critical = [v for v in vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in vulnerabilities if v['severity'] == 'High']
        
        if critical:
            recommendations.append(
                f"URGENTE: Se encontraron {len(critical)} vulnerabilidades CRÍTICAS. "
                "Requieren corrección inmediata para evitar compromiso del sistema."
            )
        
        if high:
            recommendations.append(
                f"Se encontraron {len(high)} vulnerabilidades de severidad ALTA. "
                "Priorizar corrección en las próximas 24-48 horas."
            )
        
        # Recomendaciones específicas por tipo
        sqli_vulns = [v for v in vulnerabilities if 'SQL Injection' in v['title']]
        if sqli_vulns:
            recommendations.append(
                "Implementar prepared statements y validación de entrada para prevenir SQL Injection."
            )
        
        xss_vulns = [v for v in vulnerabilities if 'XSS' in v['title']]
        if xss_vulns:
            recommendations.append(
                "Sanitizar y escapar toda entrada de usuario. Implementar Content-Security-Policy."
            )
        
        if not vulnerabilities:
            recommendations.append(
                "No se detectaron vulnerabilidades críticas en este escaneo básico. "
                "Considerar escaneo profundo para análisis completo."
            )
        
        return recommendations


def scan_vulnerabilities(target: str) -> Dict[str, any]:
    """
    Función de utilidad para escanear vulnerabilidades
    """
    scanner = VulnerabilityScanner()
    return scanner.scan(target)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python vuln_scanner.py <target>")
        print("  target puede ser: http://example.com o 192.168.1.1")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print(f"Escaneando {target} en busca de vulnerabilidades...")
    result = scan_vulnerabilities(target)
    
    print(f"\n=== Resultados del Escaneo ===")
    print(f"Target: {result['target']}")
    print(f"Tipo: {result['scan_type']}")
    print(f"Total vulnerabilidades: {result['total_vulnerabilities']}")
    print(f"  Críticas: {result['critical_count']}")
    print(f"  Altas: {result['high_count']}")
    print(f"  Medias: {result['medium_count']}")
    print(f"  Bajas: {result['low_count']}")
    print(f"CVSS Promedio: {result['average_cvss']}/10.0")
    
    if result['vulnerabilities']:
        print(f"\n=== Vulnerabilidades Encontradas ===")
        for vuln in result['vulnerabilities']:
            emoji = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(vuln['severity'], '⚪')
            
            print(f"\n{emoji} [{vuln['severity']}] {vuln['title']}")
            print(f"    CVSS: {vuln.get('cvss_score', 'N/A')}/10.0")
            print(f"    {vuln['description']}")
            if 'evidence' in vuln:
                print(f"    Evidence: {vuln['evidence']}")
            if 'remediation' in vuln:
                print(f"    Remediación: {vuln['remediation']}")
    
    if result['recommendations']:
        print(f"\n=== Recomendaciones ===")
        for rec in result['recommendations']:
            print(f"  • {rec}")