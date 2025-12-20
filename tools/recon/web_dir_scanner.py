"""
Berebrum - Web Directory Scanner
Descubrimiento de directorios y archivos en aplicaciones web
"""

import requests
import concurrent.futures
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import urljoin
import time


class WebDirectoryScanner:
    """
    Escáner de directorios y archivos web
    """
    
    # Wordlist común de directorios
    COMMON_DIRECTORIES = [
        'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'pma',
        'backup', 'backups', 'old', 'test', 'tmp', 'temp', 'cache', 'logs',
        'api', 'assets', 'css', 'js', 'images', 'img', 'uploads', 'files',
        'download', 'downloads', 'doc', 'docs', 'documentation', 'help',
        'config', 'conf', 'configure', 'settings', 'setup', 'install',
        'includes', 'include', 'inc', 'lib', 'libs', 'vendor', 'node_modules',
        'data', 'database', 'db', 'sql', 'mysql', 'private', 'public',
        'static', 'media', 'content', 'portal', 'dashboard', 'panel',
        'server-status', 'server-info', '.git', '.svn', '.env', '.htaccess'
    ]
    
    # Archivos comunes
    COMMON_FILES = [
        'robots.txt', 'sitemap.xml', '.htaccess', '.env', 'config.php',
        'configuration.php', 'settings.php', 'database.php', 'wp-config.php',
        'readme.txt', 'README.md', 'changelog.txt', 'install.php', 'setup.php',
        'phpinfo.php', 'info.php', 'test.php', 'backup.sql', 'dump.sql',
        '.git/config', '.svn/entries', 'web.config', 'crossdomain.xml',
        'clientaccesspolicy.xml', 'composer.json', 'package.json', '.DS_Store'
    ]
    
    # Códigos de estado interesantes
    INTERESTING_CODES = [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]
    
    def __init__(
        self,
        timeout: float = 5.0,
        max_workers: int = 20,
        user_agent: Optional[str] = None,
        follow_redirects: bool = False
    ):
        """
        Inicializar escáner
        
        Args:
            timeout: Timeout por petición
            max_workers: Threads concurrentes
            user_agent: User-Agent personalizado
            follow_redirects: Seguir redirecciones
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.follow_redirects = follow_redirects
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Berebrum Scanner)'
        })
    
    def scan_path(self, url: str, path: str) -> Optional[Dict[str, any]]:
        """
        Escanear una ruta específica
        
        Args:
            url: URL base
            path: Ruta a escanear
            
        Returns:
            Información del recurso si existe
        """
        full_url = urljoin(url, path)
        
        try:
            response = self.session.get(
                full_url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False  # Ignorar errores SSL para pentesting
            )
            
            # Solo reportar códigos interesantes
            if response.status_code in self.INTERESTING_CODES:
                risk_level = self._assess_risk(path, response.status_code, response)
                
                return {
                    'url': full_url,
                    'path': path,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'server': response.headers.get('Server', 'Unknown'),
                    'risk_level': risk_level,
                    'notes': self._analyze_response(path, response)
                }
            
            return None
            
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception as e:
            return None
    
    def _assess_risk(self, path: str, status_code: int, response) -> str:
        """
        Evaluar nivel de riesgo del recurso encontrado
        """
        path_lower = path.lower()
        
        # Alto riesgo: Archivos de configuración o administrativos accesibles
        critical_patterns = [
            '.env', 'config', 'database', 'wp-config', '.git', '.svn',
            'backup', '.sql', 'phpinfo', 'web.config', 'settings'
        ]
        
        if any(pattern in path_lower for pattern in critical_patterns) and status_code == 200:
            return 'Critical'
        
        # Alto riesgo: Paneles administrativos accesibles
        admin_patterns = ['admin', 'phpmyadmin', 'cpanel', 'dashboard', 'panel']
        if any(pattern in path_lower for pattern in admin_patterns):
            if status_code == 200:
                return 'High'
            elif status_code in [301, 302]:
                return 'Medium'
        
        # Medio riesgo: Directory listing habilitado
        if status_code == 200 and 'Index of' in response.text:
            return 'High'
        
        # Medio riesgo: Errores 500 (posible información sensible)
        if status_code == 500:
            return 'Medium'
        
        # Medio riesgo: 403 indica que el recurso existe pero está protegido
        if status_code == 403:
            return 'Medium'
        
        return 'Low'
    
    def _analyze_response(self, path: str, response) -> List[str]:
        """
        Analizar respuesta para generar notas
        """
        notes = []
        
        # Detectar directory listing
        if 'Index of' in response.text and response.status_code == 200:
            notes.append('Directory listing enabled')
        
        # Detectar información de versión
        if any(keyword in response.text.lower() for keyword in ['version', 'powered by']):
            notes.append('Version information exposed')
        
        # Detectar información sensible en archivos de config
        if any(pattern in path.lower() for pattern in ['.env', 'config', 'database']):
            if any(keyword in response.text.lower() for keyword in ['password', 'secret', 'key', 'token']):
                notes.append('CRITICAL: Sensitive data exposed')
        
        # Detectar errores PHP
        if 'Fatal error' in response.text or 'Warning' in response.text:
            notes.append('PHP error messages visible')
        
        # Detectar Git/SVN expuesto
        if '.git' in path.lower() or '.svn' in path.lower():
            notes.append('CRITICAL: Version control files exposed')
        
        return notes
    
    def scan(
        self,
        url: str,
        wordlist: Optional[List[str]] = None,
        scan_files: bool = True,
        scan_directories: bool = True
    ) -> Dict[str, any]:
        """
        Escanear directorios y archivos
        
        Args:
            url: URL objetivo
            wordlist: Lista personalizada de rutas
            scan_files: Escanear archivos
            scan_directories: Escanear directorios
            
        Returns:
            Resultados del escaneo
        """
        start_time = time.time()
        
        # Preparar lista de rutas a escanear
        paths_to_scan = []
        
        if wordlist:
            paths_to_scan = wordlist
        else:
            if scan_directories:
                paths_to_scan.extend(self.COMMON_DIRECTORIES)
            if scan_files:
                paths_to_scan.extend(self.COMMON_FILES)
        
        # Escanear en paralelo
        found_resources = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_path, url, path) for path in paths_to_scan]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_resources.append(result)
        
        # Ordenar por riesgo y código de estado
        found_resources.sort(key=lambda x: (
            {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x['risk_level'], 4),
            -x['status_code']
        ))
        
        duration = time.time() - start_time
        
        # Análisis de riesgos
        critical = [r for r in found_resources if r['risk_level'] == 'Critical']
        high = [r for r in found_resources if r['risk_level'] == 'High']
        medium = [r for r in found_resources if r['risk_level'] == 'Medium']
        
        return {
            'target': url,
            'total_tested': len(paths_to_scan),
            'found_count': len(found_resources),
            'resources': found_resources,
            'critical_count': len(critical),
            'high_count': len(high),
            'medium_count': len(medium),
            'duration_seconds': round(duration, 2),
            'timestamp': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(found_resources)
        }
    
    def _generate_recommendations(self, resources: List[Dict]) -> List[str]:
        """
        Generar recomendaciones de seguridad
        """
        recommendations = []
        
        critical = [r for r in resources if r['risk_level'] == 'Critical']
        if critical:
            recommendations.append(
                f"CRÍTICO: Se encontraron {len(critical)} recursos críticos expuestos "
                "(archivos de configuración, control de versiones, etc.). "
                "Eliminar o proteger inmediatamente."
            )
        
        # Verificar directory listing
        dir_listing = [r for r in resources if 'Directory listing' in str(r.get('notes', []))]
        if dir_listing:
            recommendations.append(
                f"Se encontraron {len(dir_listing)} directorios con listing habilitado. "
                "Deshabilitar directory listing en configuración del servidor."
            )
        
        # Verificar paneles administrativos
        admin_panels = [r for r in resources if any(
            pattern in r['path'].lower()
            for pattern in ['admin', 'phpmyadmin', 'panel', 'dashboard']
        )]
        if admin_panels:
            recommendations.append(
                f"Se encontraron {len(admin_panels)} paneles administrativos accesibles. "
                "Proteger con autenticación fuerte y restringir acceso por IP."
            )
        
        # Verificar archivos de backup
        backups = [r for r in resources if any(
            pattern in r['path'].lower()
            for pattern in ['backup', '.sql', '.bak', 'old']
        )]
        if backups:
            recommendations.append(
                f"Se encontraron {len(backups)} archivos de backup o antiguos. "
                "Eliminar archivos innecesarios del servidor web."
            )
        
        if not recommendations:
            recommendations.append("No se detectaron problemas críticos en las rutas escaneadas.")
        
        return recommendations
    
    def quick_scan(self, url: str) -> Dict[str, any]:
        """
        Escaneo rápido (rutas más comunes)
        """
        quick_paths = [
            'robots.txt', 'sitemap.xml', 'admin', 'login', 'phpmyadmin',
            'backup', '.env', '.git', 'config.php', 'wp-admin',
            'server-status', 'phpinfo.php', 'test.php', '.htaccess'
        ]
        
        return self.scan(url, wordlist=quick_paths)


def scan_web_directories(url: str, quick: bool = True) -> Dict[str, any]:
    """
    Función de utilidad para escanear directorios web
    """
    scanner = WebDirectoryScanner()
    
    if quick:
        return scanner.quick_scan(url)
    else:
        return scanner.scan(url)


if __name__ == '__main__':
    import sys
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if len(sys.argv) < 2:
        print("Uso: python web_dir_scanner.py <url> [quick|full]")
        sys.exit(1)
    
    url = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'quick'
    
    print(f"Escaneando directorios en {url}...")
    result = scan_web_directories(url, quick=(mode == 'quick'))
    
    print(f"\n=== Resultados del Escaneo ===")
    print(f"URL: {result['target']}")
    print(f"Probados: {result['total_tested']}")
    print(f"Encontrados: {result['found_count']}")
    print(f"Críticos: {result['critical_count']}")
    print(f"Altos: {result['high_count']}")
    print(f"Duración: {result['duration_seconds']}s")
    
    if result['resources']:
        print(f"\n=== Recursos Encontrados ===")
        for resource in result['resources']:
            risk_emoji = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(resource['risk_level'], '⚪')
            
            print(f"\n{risk_emoji} [{resource['status_code']}] {resource['url']}")
            print(f"    Size: {resource['size']} bytes")
            print(f"    Type: {resource['content_type']}")
            print(f"    Risk: {resource['risk_level']}")
            if resource['notes']:
                print(f"    Notes: {', '.join(resource['notes'])}")
    
    if result['recommendations']:
        print(f"\n=== Recomendaciones ===")
        for rec in result['recommendations']:
            print(f"  • {rec}")