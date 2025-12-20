"""
Berebrum - SSL/TLS Analyzer
Análisis de certificados SSL/TLS y configuración de seguridad
"""

import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import OpenSSL
from urllib.parse import urlparse


class SSLAnalyzer:
    """
    Analizador de certificados SSL/TLS y configuración
    """
    
    # Versiones débiles de SSL/TLS
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    # Cifrados débiles o inseguros
    WEAK_CIPHERS = [
        'DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon',
        'ADH', 'AECDH', '3DES'
    ]
    
    def __init__(self, timeout: float = 10.0):
        """
        Inicializar analizador SSL
        
        Args:
            timeout: Timeout para conexiones
        """
        self.timeout = timeout
    
    def analyze(self, url: str) -> Dict[str, any]:
        """
        Analizar certificado y configuración SSL/TLS
        
        Args:
            url: URL a analizar (https://example.com)
            
        Returns:
            Análisis completo de SSL/TLS
        """
        # Parsear URL
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        port = parsed.port or 443
        
        try:
            # Obtener certificado
            cert_info = self._get_certificate(hostname, port)
            
            # Analizar certificado
            cert_analysis = self._analyze_certificate(cert_info)
            
            # Verificar protocolos soportados
            protocol_support = self._check_protocol_support(hostname, port)
            
            # Verificar cifrados
            cipher_analysis = self._analyze_ciphers(hostname, port)
            
            # Verificar vulnerabilidades conocidas
            vulnerabilities = self._check_vulnerabilities(
                protocol_support,
                cipher_analysis,
                cert_analysis
            )
            
            # Calcular score
            security_score = self._calculate_score(
                cert_analysis,
                protocol_support,
                cipher_analysis,
                vulnerabilities
            )
            
            # Determinar riesgo
            risk_level = self._assess_risk(security_score, vulnerabilities)
            
            return {
                'hostname': hostname,
                'port': port,
                'certificate': cert_analysis,
                'protocols': protocol_support,
                'ciphers': cipher_analysis,
                'vulnerabilities': vulnerabilities,
                'security_score': security_score,
                'risk_level': risk_level,
                'recommendations': self._generate_recommendations(
                    cert_analysis,
                    protocol_support,
                    cipher_analysis,
                    vulnerabilities
                ),
                'timestamp': datetime.now().isoformat()
            }
            
        except socket.gaierror:
            return self._error_result(hostname, port, 'Hostname no resuelve')
        except socket.timeout:
            return self._error_result(hostname, port, 'Timeout')
        except ConnectionRefusedError:
            return self._error_result(hostname, port, 'Conexión rechazada')
        except ssl.SSLError as e:
            return self._error_result(hostname, port, f'Error SSL: {str(e)}')
        except Exception as e:
            return self._error_result(hostname, port, str(e))
    
    def _get_certificate(self, hostname: str, port: int) -> Dict[str, any]:
        """
        Obtener certificado del servidor
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Obtener certificado en formato PEM
                der_cert = ssock.getpeercert(binary_form=True)
                
                # Parsear con OpenSSL
                x509_cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1,
                    der_cert
                )
                
                # Obtener información
                cert_info = {
                    'version': x509_cert.get_version(),
                    'serial_number': str(x509_cert.get_serial_number()),
                    'signature_algorithm': x509_cert.get_signature_algorithm().decode(),
                    'issuer': dict(x509_cert.get_issuer().get_components()),
                    'subject': dict(x509_cert.get_subject().get_components()),
                    'not_before': datetime.strptime(
                        x509_cert.get_notBefore().decode(),
                        '%Y%m%d%H%M%SZ'
                    ),
                    'not_after': datetime.strptime(
                        x509_cert.get_notAfter().decode(),
                        '%Y%m%d%H%M%SZ'
                    ),
                    'has_expired': x509_cert.has_expired(),
                    'extensions': self._parse_extensions(x509_cert)
                }
                
                return cert_info
    
    def _parse_extensions(self, cert) -> Dict[str, any]:
        """
        Parsear extensiones del certificado
        """
        extensions = {}
        
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            ext_name = ext.get_short_name().decode()
            
            if ext_name == 'subjectAltName':
                extensions['san'] = str(ext)
            elif ext_name == 'keyUsage':
                extensions['key_usage'] = str(ext)
            elif ext_name == 'extendedKeyUsage':
                extensions['extended_key_usage'] = str(ext)
        
        return extensions
    
    def _analyze_certificate(self, cert_info: Dict) -> Dict[str, any]:
        """
        Analizar certificado
        """
        now = datetime.now()
        days_until_expiry = (cert_info['not_after'] - now).days
        
        # Verificar validez
        is_valid = not cert_info['has_expired'] and days_until_expiry > 0
        
        # Verificar algoritmo de firma
        weak_algorithms = ['md5', 'sha1']
        sig_algo = cert_info['signature_algorithm'].lower()
        has_weak_signature = any(weak in sig_algo for weak in weak_algorithms)
        
        # Verificar tiempo de validez
        expiring_soon = 0 < days_until_expiry <= 30
        
        # Obtener información del issuer y subject
        issuer_cn = cert_info['issuer'].get(b'CN', b'Unknown').decode()
        subject_cn = cert_info['subject'].get(b'CN', b'Unknown').decode()
        
        # Verificar si es self-signed
        is_self_signed = issuer_cn == subject_cn
        
        return {
            'is_valid': is_valid,
            'has_expired': cert_info['has_expired'],
            'not_before': cert_info['not_before'].isoformat(),
            'not_after': cert_info['not_after'].isoformat(),
            'days_until_expiry': days_until_expiry,
            'expiring_soon': expiring_soon,
            'issuer': issuer_cn,
            'subject': subject_cn,
            'is_self_signed': is_self_signed,
            'signature_algorithm': cert_info['signature_algorithm'],
            'has_weak_signature': has_weak_signature,
            'san': cert_info['extensions'].get('san'),
            'issues': self._identify_cert_issues(
                is_valid,
                is_self_signed,
                has_weak_signature,
                expiring_soon,
                days_until_expiry
            )
        }
    
    def _identify_cert_issues(
        self,
        is_valid: bool,
        is_self_signed: bool,
        has_weak_signature: bool,
        expiring_soon: bool,
        days_until_expiry: int
    ) -> List[Dict]:
        """
        Identificar problemas en el certificado
        """
        issues = []
        
        if not is_valid:
            issues.append({
                'severity': 'Critical',
                'issue': 'Certificate Expired or Not Yet Valid',
                'description': 'El certificado no es válido en el tiempo actual'
            })
        
        if is_self_signed:
            issues.append({
                'severity': 'High',
                'issue': 'Self-Signed Certificate',
                'description': 'El certificado es auto-firmado (no confiable públicamente)'
            })
        
        if has_weak_signature:
            issues.append({
                'severity': 'High',
                'issue': 'Weak Signature Algorithm',
                'description': 'El certificado usa un algoritmo de firma débil (MD5/SHA1)'
            })
        
        if expiring_soon:
            issues.append({
                'severity': 'Medium',
                'issue': 'Certificate Expiring Soon',
                'description': f'El certificado expira en {days_until_expiry} días'
            })
        
        return issues
    
    def _check_protocol_support(self, hostname: str, port: int) -> Dict[str, any]:
        """
        Verificar qué protocolos SSL/TLS están soportados
        """
        protocols_to_test = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Deshabilitado en Python moderno
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
        }
        
        supported = []
        weak_protocols_found = []
        
        for protocol_name, protocol_const in protocols_to_test.items():
            if protocol_const is None:
                continue
            
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported.append(protocol_name)
                        
                        if protocol_name in self.WEAK_PROTOCOLS:
                            weak_protocols_found.append(protocol_name)
            except:
                pass
        
        return {
            'supported': supported,
            'weak_protocols': weak_protocols_found,
            'has_weak_protocols': len(weak_protocols_found) > 0
        }
    
    def _analyze_ciphers(self, hostname: str, port: int) -> Dict[str, any]:
        """
        Analizar cifrados soportados
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    # Verificar si el cifrado es débil
                    cipher_name = cipher[0]
                    is_weak = any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS)
                    
                    return {
                        'current_cipher': cipher_name,
                        'protocol': cipher[1],
                        'bits': cipher[2],
                        'is_weak': is_weak
                    }
        except:
            return {
                'current_cipher': 'Unknown',
                'protocol': 'Unknown',
                'bits': 0,
                'is_weak': False
            }
    
    def _check_vulnerabilities(
        self,
        protocol_support: Dict,
        cipher_analysis: Dict,
        cert_analysis: Dict
    ) -> List[Dict]:
        """
        Verificar vulnerabilidades conocidas
        """
        vulnerabilities = []
        
        # POODLE (SSLv3)
        if 'SSLv3' in protocol_support['supported']:
            vulnerabilities.append({
                'name': 'POODLE',
                'cve': 'CVE-2014-3566',
                'severity': 'High',
                'description': 'Vulnerable a POODLE attack debido a soporte de SSLv3'
            })
        
        # BEAST (TLSv1.0)
        if 'TLSv1' in protocol_support['supported']:
            vulnerabilities.append({
                'name': 'BEAST',
                'cve': 'CVE-2011-3389',
                'severity': 'Medium',
                'description': 'Potencialmente vulnerable a BEAST attack con TLSv1.0'
            })
        
        # Cifrados débiles
        if cipher_analysis['is_weak']:
            vulnerabilities.append({
                'name': 'Weak Cipher',
                'severity': 'High',
                'description': f"Usando cifrado débil: {cipher_analysis['current_cipher']}"
            })
        
        # Certificado expirado
        if not cert_analysis['is_valid']:
            vulnerabilities.append({
                'name': 'Invalid Certificate',
                'severity': 'Critical',
                'description': 'Certificado expirado o no válido'
            })
        
        return vulnerabilities
    
    def _calculate_score(
        self,
        cert_analysis: Dict,
        protocol_support: Dict,
        cipher_analysis: Dict,
        vulnerabilities: List
    ) -> int:
        """
        Calcular score de seguridad (0-100)
        """
        score = 100
        
        # Penalizar por certificado
        if not cert_analysis['is_valid']:
            score -= 40
        elif cert_analysis['is_self_signed']:
            score -= 20
        
        if cert_analysis['has_weak_signature']:
            score -= 15
        
        # Penalizar por protocolos débiles
        score -= len(protocol_support['weak_protocols']) * 15
        
        # Penalizar por cifrados débiles
        if cipher_analysis['is_weak']:
            score -= 20
        
        # Penalizar por vulnerabilidades
        for vuln in vulnerabilities:
            if vuln['severity'] == 'Critical':
                score -= 25
            elif vuln['severity'] == 'High':
                score -= 15
            elif vuln['severity'] == 'Medium':
                score -= 10
        
        return max(0, score)
    
    def _assess_risk(self, score: int, vulnerabilities: List) -> str:
        """
        Evaluar riesgo general
        """
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        
        if critical_vulns or score < 40:
            return 'Critical'
        elif score < 60:
            return 'High'
        elif score < 80:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_recommendations(
        self,
        cert_analysis: Dict,
        protocol_support: Dict,
        cipher_analysis: Dict,
        vulnerabilities: List
    ) -> List[str]:
        """
        Generar recomendaciones
        """
        recommendations = []
        
        # Certificado
        if not cert_analysis['is_valid']:
            recommendations.append(
                "CRÍTICO: Renovar certificado SSL/TLS inmediatamente. "
                "Los navegadores mostrarán advertencias de seguridad."
            )
        elif cert_analysis['expiring_soon']:
            recommendations.append(
                f"Certificado expira en {cert_analysis['days_until_expiry']} días. Renovar pronto."
            )
        
        if cert_analysis['is_self_signed']:
            recommendations.append(
                "Obtener certificado de una CA confiable (Let's Encrypt, etc.)"
            )
        
        # Protocolos
        if protocol_support['has_weak_protocols']:
            recommendations.append(
                f"Deshabilitar protocolos débiles: {', '.join(protocol_support['weak_protocols'])}. "
                "Usar solo TLSv1.2 y TLSv1.3."
            )
        
        # Cifrados
        if cipher_analysis['is_weak']:
            recommendations.append(
                "Deshabilitar cifrados débiles y usar solo cipher suites modernos."
            )
        
        # Vulnerabilidades
        if vulnerabilities:
            recommendations.append(
                f"Corregir {len(vulnerabilities)} vulnerabilidades detectadas. "
                "Revisar configuración del servidor web."
            )
        
        if not recommendations:
            recommendations.append(
                "La configuración SSL/TLS es buena. Sin problemas críticos detectados."
            )
        
        return recommendations
    
    def _error_result(self, hostname: str, port: int, error: str) -> Dict[str, any]:
        """
        Resultado de error
        """
        return {
            'hostname': hostname,
            'port': port,
            'error': error,
            'security_score': 0,
            'risk_level': 'Unknown',
            'timestamp': datetime.now().isoformat()
        }


def analyze_ssl(url: str) -> Dict[str, any]:
    """
    Función de utilidad para analizar SSL
    """
    analyzer = SSLAnalyzer()
    return analyzer.analyze(url)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python ssl_analyzer.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    
    print(f"Analizando SSL/TLS de {url}...")
    result = analyze_ssl(url)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print(f"\n=== Análisis SSL/TLS ===")
    print(f"Host: {result['hostname']}:{result['port']}")
    print(f"Security Score: {result['security_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    
    # Certificado
    cert = result['certificate']
    print(f"\n--- Certificado ---")
    print(f"Válido: {'✓' if cert['is_valid'] else '✗'}")
    print(f"Emisor: {cert['issuer']}")
    print(f"Sujeto: {cert['subject']}")
    print(f"Expira: {cert['not_after']} ({cert['days_until_expiry']} días)")
    print(f"Auto-firmado: {'Sí' if cert['is_self_signed'] else 'No'}")
    
    if cert['issues']:
        print(f"\nProblemas del certificado:")
        for issue in cert['issues']:
            print(f"  [{issue['severity']}] {issue['issue']}")
            print(f"    {issue['description']}")
    
    # Protocolos
    print(f"\n--- Protocolos Soportados ---")
    for proto in result['protocols']['supported']:
        weak = '⚠' if proto in result['protocols']['weak_protocols'] else '✓'
        print(f"  {weak} {proto}")
    
    # Cifrados
    print(f"\n--- Cifrado Actual ---")
    print(f"  {result['ciphers']['current_cipher']} ({result['ciphers']['bits']} bits)")
    if result['ciphers']['is_weak']:
        print(f"  ⚠ ADVERTENCIA: Cifrado débil")
    
    # Vulnerabilidades
    if result['vulnerabilities']:
        print(f"\n--- Vulnerabilidades ({len(result['vulnerabilities'])}) ---")
        for vuln in result['vulnerabilities']:
            print(f"  [{vuln['severity']}] {vuln['name']}")
            print(f"    {vuln['description']}")
    
    # Recomendaciones
    if result['recommendations']:
        print(f"\n=== Recomendaciones ===")
        for rec in result['recommendations']:
            print(f"  • {rec}")