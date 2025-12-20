"""
Berebrum - HTTP Header Analyzer
Análisis de headers de seguridad HTTP
"""

import requests
from typing import Dict, List, Optional
from datetime import datetime
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPHeaderAnalyzer:
    """
    Analizador de headers HTTP y headers de seguridad
    """
    
    # Headers de seguridad esperados
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HSTS - Fuerza uso de HTTPS',
            'risk_if_missing': 'High',
            'recommendation': 'Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'description': 'CSP - Previene XSS y otros ataques',
            'risk_if_missing': 'High',
            'recommendation': 'Implementar política CSP restrictiva'
        },
        'X-Frame-Options': {
            'description': 'Previene ataques de clickjacking',
            'risk_if_missing': 'Medium',
            'recommendation': 'Agregar: X-Frame-Options: DENY o SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'Previene MIME-sniffing',
            'risk_if_missing': 'Medium',
            'recommendation': 'Agregar: X-Content-Type-Options: nosniff'
        },
        'X-XSS-Protection': {
            'description': 'Protección XSS del navegador',
            'risk_if_missing': 'Low',
            'recommendation': 'Agregar: X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'description': 'Control de información del referrer',
            'risk_if_missing': 'Low',
            'recommendation': 'Agregar: Referrer-Policy: no-referrer o strict-origin'
        },
        'Permissions-Policy': {
            'description': 'Control de permisos del navegador',
            'risk_if_missing': 'Low',
            'recommendation': 'Implementar política de permisos restrictiva'
        }
    }
    
    # Headers que revelan información
    INFORMATION_DISCLOSURE_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
        'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via'
    ]
    
    def __init__(self, timeout: float = 10.0):
        """
        Inicializar analizador
        
        Args:
            timeout: Timeout para peticiones
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Berebrum Header Analyzer)'
        })
    
    def analyze(self, url: str) -> Dict[str, any]:
        """
        Analizar headers HTTP de una URL
        
        Args:
            url: URL a analizar
            
        Returns:
            Análisis completo de headers
        """
        try:
            # Realizar petición
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            # Analizar headers
            headers = dict(response.headers)
            
            # Verificar headers de seguridad
            security_analysis = self._analyze_security_headers(headers)
            
            # Verificar información expuesta
            info_disclosure = self._analyze_information_disclosure(headers)
            
            # Analizar cookies
            cookie_analysis = self._analyze_cookies(response.cookies)
            
            # Calcular score de seguridad
            security_score = self._calculate_security_score(
                security_analysis,
                info_disclosure,
                cookie_analysis
            )
            
            # Determinar nivel de riesgo
            risk_level = self._assess_overall_risk(security_score)
            
            return {
                'url': url,
                'status_code': response.status_code,
                'headers': headers,
                'security_headers': security_analysis,
                'information_disclosure': info_disclosure,
                'cookies': cookie_analysis,
                'security_score': security_score,
                'risk_level': risk_level,
                'recommendations': self._generate_recommendations(
                    security_analysis,
                    info_disclosure,
                    cookie_analysis
                ),
                'timestamp': datetime.now().isoformat()
            }
            
        except requests.exceptions.Timeout:
            return self._error_result(url, 'Timeout')
        except requests.exceptions.ConnectionError:
            return self._error_result(url, 'Connection error')
        except Exception as e:
            return self._error_result(url, str(e))
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, any]:
        """
        Analizar headers de seguridad
        """
        analysis = {
            'present': [],
            'missing': [],
            'misconfigured': []
        }
        
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name in headers:
                # Header presente, verificar si está bien configurado
                value = headers[header_name]
                config_check = self._check_header_configuration(header_name, value)
                
                analysis['present'].append({
                    'header': header_name,
                    'value': value,
                    'description': header_info['description'],
                    'properly_configured': config_check['valid'],
                    'notes': config_check['notes']
                })
                
                if not config_check['valid']:
                    analysis['misconfigured'].append(header_name)
            else:
                # Header ausente
                analysis['missing'].append({
                    'header': header_name,
                    'description': header_info['description'],
                    'risk_level': header_info['risk_if_missing'],
                    'recommendation': header_info['recommendation']
                })
        
        return analysis
    
    def _check_header_configuration(self, header: str, value: str) -> Dict[str, any]:
        """
        Verificar si un header está bien configurado
        """
        notes = []
        valid = True
        
        if header == 'Strict-Transport-Security':
            if 'max-age' not in value.lower():
                notes.append('Falta directiva max-age')
                valid = False
            if 'includesubdomains' not in value.lower():
                notes.append('Considerar agregar includeSubDomains')
        
        elif header == 'Content-Security-Policy':
            if 'unsafe-inline' in value.lower():
                notes.append('Uso de unsafe-inline reduce efectividad de CSP')
                valid = False
            if 'unsafe-eval' in value.lower():
                notes.append('Uso de unsafe-eval reduce efectividad de CSP')
                valid = False
        
        elif header == 'X-Frame-Options':
            if value.upper() not in ['DENY', 'SAMEORIGIN']:
                notes.append('Valor debería ser DENY o SAMEORIGIN')
                valid = False
        
        elif header == 'X-Content-Type-Options':
            if value.lower() != 'nosniff':
                notes.append('Valor debería ser nosniff')
                valid = False
        
        elif header == 'X-XSS-Protection':
            if '1' not in value:
                notes.append('XSS Protection debería estar habilitada')
                valid = False
        
        return {'valid': valid, 'notes': notes}
    
    def _analyze_information_disclosure(self, headers: Dict[str, str]) -> Dict[str, any]:
        """
        Analizar headers que revelan información
        """
        disclosed_info = []
        
        for header in self.INFORMATION_DISCLOSURE_HEADERS:
            if header in headers:
                disclosed_info.append({
                    'header': header,
                    'value': headers[header],
                    'risk': 'Medium' if header in ['Server', 'X-Powered-By'] else 'Low'
                })
        
        return {
            'count': len(disclosed_info),
            'headers': disclosed_info,
            'has_disclosure': len(disclosed_info) > 0
        }
    
    def _analyze_cookies(self, cookies) -> Dict[str, any]:
        """
        Analizar configuración de cookies
        """
        insecure_cookies = []
        
        for cookie in cookies:
            issues = []
            
            if not cookie.secure:
                issues.append('Missing Secure flag')
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('Missing HttpOnly flag')
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append('Missing SameSite attribute')
            
            if issues:
                insecure_cookies.append({
                    'name': cookie.name,
                    'issues': issues,
                    'risk_level': 'High' if 'Missing Secure flag' in issues else 'Medium'
                })
        
        return {
            'total_cookies': len(cookies),
            'insecure_count': len(insecure_cookies),
            'insecure_cookies': insecure_cookies
        }
    
    def _calculate_security_score(
        self,
        security_analysis: Dict,
        info_disclosure: Dict,
        cookie_analysis: Dict
    ) -> int:
        """
        Calcular score de seguridad (0-100)
        """
        score = 100
        
        # Penalizar por headers de seguridad faltantes
        for missing in security_analysis['missing']:
            if missing['risk_level'] == 'High':
                score -= 15
            elif missing['risk_level'] == 'Medium':
                score -= 10
            else:
                score -= 5
        
        # Penalizar por headers mal configurados
        score -= len(security_analysis['misconfigured']) * 10
        
        # Penalizar por información expuesta
        score -= info_disclosure['count'] * 5
        
        # Penalizar por cookies inseguras
        score -= cookie_analysis['insecure_count'] * 10
        
        return max(0, score)
    
    def _assess_overall_risk(self, score: int) -> str:
        """
        Evaluar riesgo general basado en el score
        """
        if score >= 80:
            return 'Low'
        elif score >= 60:
            return 'Medium'
        elif score >= 40:
            return 'High'
        else:
            return 'Critical'
    
    def _generate_recommendations(
        self,
        security_analysis: Dict,
        info_disclosure: Dict,
        cookie_analysis: Dict
    ) -> List[str]:
        """
        Generar recomendaciones de seguridad
        """
        recommendations = []
        
        # Headers faltantes de alto riesgo
        high_risk_missing = [
            h for h in security_analysis['missing']
            if h['risk_level'] == 'High'
        ]
        
        if high_risk_missing:
            recommendations.append(
                f"CRÍTICO: Faltan {len(high_risk_missing)} headers de seguridad importantes: "
                f"{', '.join([h['header'] for h in high_risk_missing])}"
            )
        
        # Headers mal configurados
        if security_analysis['misconfigured']:
            recommendations.append(
                f"Revisar configuración de headers: {', '.join(security_analysis['misconfigured'])}"
            )
        
        # Información expuesta
        if info_disclosure['has_disclosure']:
            recommendations.append(
                f"Se están exponiendo {info_disclosure['count']} headers informativos. "
                "Considerar ocultar versiones de servidor y frameworks."
            )
        
        # Cookies inseguras
        if cookie_analysis['insecure_count'] > 0:
            recommendations.append(
                f"Se encontraron {cookie_analysis['insecure_count']} cookies con configuración insegura. "
                "Habilitar flags Secure, HttpOnly y SameSite."
            )
        
        if not recommendations:
            recommendations.append("La configuración de headers es buena. Sin problemas críticos detectados.")
        
        return recommendations
    
    def _error_result(self, url: str, error: str) -> Dict[str, any]:
        """
        Resultado de error
        """
        return {
            'url': url,
            'error': error,
            'security_score': 0,
            'risk_level': 'Unknown',
            'timestamp': datetime.now().isoformat()
        }


def analyze_headers(url: str) -> Dict[str, any]:
    """
    Función de utilidad para analizar headers
    """
    analyzer = HTTPHeaderAnalyzer()
    return analyzer.analyze(url)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python header_analyzer.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    
    print(f"Analizando headers de {url}...")
    result = analyze_headers(url)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print(f"\n=== Análisis de Headers HTTP ===")
    print(f"URL: {result['url']}")
    print(f"Status: {result['status_code']}")
    print(f"Security Score: {result['security_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    
    # Headers de seguridad presentes
    if result['security_headers']['present']:
        print(f"\n✓ Headers de Seguridad Presentes:")
        for header in result['security_headers']['present']:
            status = '✓' if header['properly_configured'] else '⚠'
            print(f"  {status} {header['header']}: {header['value'][:60]}")
            if header['notes']:
                for note in header['notes']:
                    print(f"      • {note}")
    
    # Headers de seguridad faltantes
    if result['security_headers']['missing']:
        print(f"\n✗ Headers de Seguridad Faltantes:")
        for header in result['security_headers']['missing']:
            print(f"  [{header['risk_level']}] {header['header']}")
            print(f"      {header['description']}")
    
    # Información expuesta
    if result['information_disclosure']['has_disclosure']:
        print(f"\n⚠ Información Expuesta:")
        for header in result['information_disclosure']['headers']:
            print(f"  {header['header']}: {header['value']}")
    
    # Cookies inseguras
    if result['cookies']['insecure_count'] > 0:
        print(f"\n⚠ Cookies Inseguras ({result['cookies']['insecure_count']}):")
        for cookie in result['cookies']['insecure_cookies']:
            print(f"  {cookie['name']}: {', '.join(cookie['issues'])}")
    
    # Recomendaciones
    if result['recommendations']:
        print(f"\n=== Recomendaciones ===")
        for rec in result['recommendations']:
            print(f"  • {rec}")