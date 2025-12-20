"""
Berebrum - Subdomain Enumerator
Enumeración de subdominios mediante DNS brute force y técnicas pasivas
"""

import socket
import dns.resolver
import concurrent.futures
from typing import List, Dict, Set, Optional
from datetime import datetime
import time


class SubdomainEnumerator:
    """
    Enumerador de subdominios usando múltiples técnicas
    """
    
    # Wordlist común de subdominios
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'dev', 'staging', 'test',
        'admin', 'api', 'blog', 'forum', 'shop', 'store', 'mobile', 'm', 'app', 'apps',
        'portal', 'vpn', 'remote', 'ssh', 'git', 'svn', 'db', 'database', 'mysql',
        'secure', 'beta', 'demo', 'cdn', 'static', 'images', 'img', 'media', 'assets',
        'cloud', 'backup', 'monitor', 'monitoring', 'log', 'logs', 'analytics',
        'intranet', 'extranet', 'internal', 'external', 'private', 'public',
        'old', 'new', 'uat', 'prod', 'production', 'support', 'help', 'docs',
        'status', 'dashboard', 'panel', 'control', 'cpanel', 'plesk', 'webmin',
        'phpmyadmin', 'pma', 'adminer', 'grafana', 'kibana', 'jenkins', 'gitlab',
        'jira', 'confluence', 'wiki', 'redmine', 'nexus', 'artifactory'
    ]
    
    def __init__(
        self,
        timeout: float = 2.0,
        max_workers: int = 50,
        nameservers: Optional[List[str]] = None
    ):
        """
        Inicializar enumerador
        
        Args:
            timeout: Timeout por consulta DNS
            max_workers: Threads concurrentes
            nameservers: Servidores DNS personalizados
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        if nameservers:
            self.resolver.nameservers = nameservers
    
    def resolve_subdomain(self, subdomain: str, domain: str) -> Optional[Dict[str, any]]:
        """
        Resolver un subdominio
        
        Args:
            subdomain: Subdominio a probar
            domain: Dominio base
            
        Returns:
            Información del subdominio si existe
        """
        full_domain = f"{subdomain}.{domain}"
        
        try:
            # Intentar resolver A record
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Intentar obtener CNAME
            cname = None
            try:
                cname_answers = self.resolver.resolve(full_domain, 'CNAME')
                cname = str(cname_answers[0])
            except:
                pass
            
            # Verificar si responde HTTP/HTTPS
            http_status = self._check_http(full_domain)
            
            return {
                'subdomain': subdomain,
                'full_domain': full_domain,
                'ips': ips,
                'cname': cname,
                'http_status': http_status,
                'risk_level': self._assess_subdomain_risk(subdomain, http_status)
            }
            
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except Exception as e:
            return None
    
    def _check_http(self, domain: str) -> Dict[str, bool]:
        """
        Verificar si el subdominio responde HTTP/HTTPS
        """
        http_responds = False
        https_responds = False
        
        # Check HTTP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((domain, 80))
            http_responds = (result == 0)
            sock.close()
        except:
            pass
        
        # Check HTTPS
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((domain, 443))
            https_responds = (result == 0)
            sock.close()
        except:
            pass
        
        return {
            'http': http_responds,
            'https': https_responds
        }
    
    def _assess_subdomain_risk(self, subdomain: str, http_status: Dict) -> str:
        """
        Evaluar riesgo del subdominio
        """
        high_risk_keywords = [
            'admin', 'cpanel', 'phpmyadmin', 'pma', 'webmin', 'plesk',
            'backup', 'db', 'database', 'mysql', 'postgres', 'mongo',
            'jenkins', 'gitlab', 'internal', 'private', 'vpn', 'remote',
            'test', 'dev', 'staging', 'old', 'beta'
        ]
        
        medium_risk_keywords = [
            'api', 'portal', 'panel', 'dashboard', 'control', 'monitor',
            'logs', 'status', 'grafana', 'kibana', 'jira', 'confluence'
        ]
        
        subdomain_lower = subdomain.lower()
        
        # Alto riesgo si es un subdominio administrativo
        if any(keyword in subdomain_lower for keyword in high_risk_keywords):
            return 'High'
        
        # Medio riesgo si es un subdominio de servicios
        if any(keyword in subdomain_lower for keyword in medium_risk_keywords):
            return 'Medium'
        
        # HTTP sin HTTPS es riesgo medio
        if http_status['http'] and not http_status['https']:
            return 'Medium'
        
        return 'Low'
    
    def enumerate(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        use_common_only: bool = True
    ) -> Dict[str, any]:
        """
        Enumerar subdominios
        
        Args:
            domain: Dominio base
            wordlist: Lista personalizada de subdominios
            use_common_only: Usar solo subdominios comunes
            
        Returns:
            Resultados de la enumeración
        """
        start_time = time.time()
        
        # Determinar lista de subdominios a probar
        if wordlist:
            subdomains_to_test = wordlist
        elif use_common_only:
            subdomains_to_test = self.COMMON_SUBDOMAINS
        else:
            subdomains_to_test = self._load_extended_wordlist()
        
        found_subdomains = []
        
        # Probar subdominios en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self.resolve_subdomain, subdomain, domain)
                for subdomain in subdomains_to_test
            ]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
        
        # Ordenar por riesgo y nombre
        found_subdomains.sort(key=lambda x: (
            {'High': 0, 'Medium': 1, 'Low': 2}.get(x['risk_level'], 3),
            x['subdomain']
        ))
        
        duration = time.time() - start_time
        
        # Análisis de riesgos
        high_risk = [s for s in found_subdomains if s['risk_level'] == 'High']
        medium_risk = [s for s in found_subdomains if s['risk_level'] == 'Medium']
        
        return {
            'domain': domain,
            'total_tested': len(subdomains_to_test),
            'found_count': len(found_subdomains),
            'subdomains': found_subdomains,
            'high_risk_count': len(high_risk),
            'medium_risk_count': len(medium_risk),
            'duration_seconds': round(duration, 2),
            'timestamp': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(found_subdomains)
        }
    
    def _load_extended_wordlist(self) -> List[str]:
        """
        Cargar wordlist extendida (para uso futuro)
        """
        # Por ahora, retornar la lista común
        # En el futuro, esto podría cargar desde un archivo
        return self.COMMON_SUBDOMAINS
    
    def _generate_recommendations(self, subdomains: List[Dict]) -> List[str]:
        """
        Generar recomendaciones de seguridad
        """
        recommendations = []
        
        high_risk = [s for s in subdomains if s['risk_level'] == 'High']
        
        if high_risk:
            recommendations.append(
                f"Se encontraron {len(high_risk)} subdominios de alto riesgo (admin, db, backup, etc.). "
                "Verificar que estén protegidos con autenticación fuerte y restringidos por IP."
            )
        
        # Verificar subdominios con solo HTTP
        http_only = [s for s in subdomains if s['http_status']['http'] and not s['http_status']['https']]
        if http_only:
            recommendations.append(
                f"Se encontraron {len(http_only)} subdominios con solo HTTP (sin HTTPS). "
                "Implementar certificados SSL/TLS para todos los subdominios."
            )
        
        # Verificar subdominios de desarrollo/staging
        dev_subdomains = [
            s for s in subdomains
            if any(keyword in s['subdomain'].lower() for keyword in ['dev', 'test', 'staging', 'beta', 'old'])
        ]
        if dev_subdomains:
            recommendations.append(
                f"Se encontraron {len(dev_subdomains)} subdominios de desarrollo/staging expuestos. "
                "Considerar eliminar o proteger estos entornos de la red pública."
            )
        
        if not recommendations:
            recommendations.append("No se detectaron problemas críticos en los subdominios encontrados.")
        
        return recommendations
    
    def quick_enum(self, domain: str) -> Dict[str, any]:
        """
        Enumeración rápida (top 30 subdominios)
        """
        top_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'cpanel', 'webmail', 'api',
            'blog', 'dev', 'staging', 'test', 'mobile', 'shop', 'portal',
            'secure', 'vpn', 'remote', 'db', 'mysql', 'backup', 'monitor',
            'status', 'dashboard', 'panel', 'git', 'jenkins', 'gitlab',
            'old', 'new', 'beta'
        ]
        
        return self.enumerate(domain, wordlist=top_subdomains)


def enumerate_subdomains(domain: str, quick: bool = True) -> Dict[str, any]:
    """
    Función de utilidad para enumerar subdominios
    """
    enumerator = SubdomainEnumerator()
    
    if quick:
        return enumerator.quick_enum(domain)
    else:
        return enumerator.enumerate(domain)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python subdomain_enum.py <domain> [quick|full]")
        sys.exit(1)
    
    domain = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'quick'
    
    print(f"Enumerando subdominios de {domain}...")
    result = enumerate_subdomains(domain, quick=(mode == 'quick'))
    
    print(f"\n=== Resultados de Enumeración ===")
    print(f"Dominio: {result['domain']}")
    print(f"Probados: {result['total_tested']}")
    print(f"Encontrados: {result['found_count']}")
    print(f"Alto riesgo: {result['high_risk_count']}")
    print(f"Duración: {result['duration_seconds']}s")
    
    if result['subdomains']:
        print(f"\n=== Subdominios Encontrados ===")
        for sub in result['subdomains']:
            http_status = '🌐 HTTP' if sub['http_status']['http'] else ''
            https_status = '🔒 HTTPS' if sub['http_status']['https'] else ''
            print(f"  [{sub['risk_level']}] {sub['full_domain']}")
            print(f"    IPs: {', '.join(sub['ips'])}")
            print(f"    Status: {http_status} {https_status}")
            if sub['cname']:
                print(f"    CNAME: {sub['cname']}")
    
    if result['recommendations']:
        print(f"\n=== Recomendaciones ===")
        for rec in result['recommendations']:
            print(f"  • {rec}")