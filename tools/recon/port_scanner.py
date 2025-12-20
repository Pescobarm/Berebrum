"""
Berebrum - Port Scanner Tool
Escaneo de puertos TCP con detección de servicios
"""

import socket
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import time


class PortScanner:
    """
    Escáner de puertos TCP básico con detección de servicios comunes
    """
    
    # Puertos comunes y sus servicios
    COMMON_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        27017: 'MongoDB', 9200: 'Elasticsearch'
    }
    
    # Puertos según categoría
    CRITICAL_PORTS = [22, 23, 3389, 5900]  # Acceso remoto
    HIGH_RISK_PORTS = [21, 445, 1433, 3306, 5432, 6379, 27017]  # Bases de datos y file sharing
    MEDIUM_RISK_PORTS = [25, 110, 143, 8080, 8443]  # Email y proxies
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """
        Inicializar escáner
        
        Args:
            timeout: Timeout por puerto en segundos
            max_workers: Número máximo de threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        
    def scan_port(self, target: str, port: int) -> Tuple[int, bool, Optional[str]]:
        """
        Escanear un puerto específico
        
        Args:
            target: IP o hostname
            port: Puerto a escanear
            
        Returns:
            Tupla (puerto, abierto, servicio)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            is_open = (result == 0)
            service = self.COMMON_PORTS.get(port, 'Unknown')
            
            return (port, is_open, service if is_open else None)
        except socket.gaierror:
            return (port, False, None)
        except socket.error:
            return (port, False, None)
    
    def grab_banner(self, target: str, port: int) -> Optional[str]:
        """
        Intentar obtener el banner del servicio
        
        Args:
            target: IP o hostname
            port: Puerto del servicio
            
        Returns:
            Banner del servicio o None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target, port))
            
            # Enviar una petición básica para obtener respuesta
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except:
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
        except:
            return None
    
    def scan_ports(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        port_range: Optional[Tuple[int, int]] = None
    ) -> Dict[str, any]:
        """
        Escanear múltiples puertos
        
        Args:
            target: IP o hostname a escanear
            ports: Lista de puertos específicos (opcional)
            port_range: Rango de puertos (inicio, fin) (opcional)
            
        Returns:
            Diccionario con resultados del escaneo
        """
        start_time = time.time()
        
        # Determinar qué puertos escanear
        if ports:
            ports_to_scan = ports
        elif port_range:
            ports_to_scan = range(port_range[0], port_range[1] + 1)
        else:
            # Por defecto, escanear puertos comunes
            ports_to_scan = list(self.COMMON_PORTS.keys())
        
        # Escanear puertos en paralelo
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_port, target, port) for port in ports_to_scan]
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    # Intentar obtener banner
                    banner = self.grab_banner(target, port)
                    
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'risk_level': self._assess_risk(port)
                    })
        
        # Ordenar por puerto
        open_ports.sort(key=lambda x: x['port'])
        
        duration = time.time() - start_time
        
        return {
            'target': target,
            'total_ports_scanned': len(ports_to_scan),
            'open_ports_count': len(open_ports),
            'open_ports': open_ports,
            'duration_seconds': round(duration, 2),
            'scan_time': datetime.now().isoformat(),
            'critical_services': self._get_critical_services(open_ports),
            'recommendations': self._generate_recommendations(open_ports)
        }
    
    def _assess_risk(self, port: int) -> str:
        """
        Evaluar el nivel de riesgo de un puerto abierto
        
        Args:
            port: Número de puerto
            
        Returns:
            Nivel de riesgo: 'Critical', 'High', 'Medium', 'Low'
        """
        if port in self.CRITICAL_PORTS:
            return 'Critical'
        elif port in self.HIGH_RISK_PORTS:
            return 'High'
        elif port in self.MEDIUM_RISK_PORTS:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_critical_services(self, open_ports: List[Dict]) -> List[Dict]:
        """
        Filtrar servicios críticos encontrados
        
        Args:
            open_ports: Lista de puertos abiertos
            
        Returns:
            Lista de servicios críticos
        """
        return [p for p in open_ports if p['risk_level'] in ['Critical', 'High']]
    
    def _generate_recommendations(self, open_ports: List[Dict]) -> List[str]:
        """
        Generar recomendaciones de seguridad
        
        Args:
            open_ports: Lista de puertos abiertos
            
        Returns:
            Lista de recomendaciones
        """
        recommendations = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            if port in [22, 3389, 5900]:
                recommendations.append(
                    f"Puerto {port} ({service}): Implementar autenticación de dos factores y restringir acceso por IP"
                )
            
            if port in [23]:
                recommendations.append(
                    f"Puerto {port} ({service}): CRÍTICO - Telnet sin cifrado. Cambiar a SSH inmediatamente"
                )
            
            if port in [21]:
                recommendations.append(
                    f"Puerto {port} ({service}): Considerar SFTP/FTPS. Deshabilitar acceso anónimo"
                )
            
            if port in [445]:
                recommendations.append(
                    f"Puerto {port} ({service}): Actualizar SMB, deshabilitar SMBv1, restringir acceso"
                )
            
            if port in [3306, 5432, 1433, 27017, 6379]:
                recommendations.append(
                    f"Puerto {port} ({service}): Base de datos expuesta. Restringir a IPs autorizadas"
                )
        
        if not recommendations:
            recommendations.append("No se detectaron servicios críticos expuestos")
        
        return recommendations
    
    def quick_scan(self, target: str) -> Dict[str, any]:
        """
        Escaneo rápido de puertos más comunes (top 20)
        
        Args:
            target: IP o hostname
            
        Returns:
            Resultado del escaneo
        """
        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080
        ]
        
        return self.scan_ports(target, ports=top_ports)
    
    def full_scan(self, target: str) -> Dict[str, any]:
        """
        Escaneo completo de todos los puertos (1-65535)
        ADVERTENCIA: Puede tomar mucho tiempo
        
        Args:
            target: IP o hostname
            
        Returns:
            Resultado del escaneo
        """
        return self.scan_ports(target, port_range=(1, 65535))


# Función de utilidad para uso desde CLI
def scan_target(target: str, scan_type: str = 'quick') -> Dict[str, any]:
    """
    Función de utilidad para escanear un target
    
    Args:
        target: IP o hostname
        scan_type: 'quick' (top 20), 'common' (puertos comunes), 'full' (todos)
        
    Returns:
        Resultado del escaneo
    """
    scanner = PortScanner()
    
    if scan_type == 'quick':
        return scanner.quick_scan(target)
    elif scan_type == 'full':
        return scanner.full_scan(target)
    else:  # common
        return scanner.scan_ports(target)


if __name__ == '__main__':
    # Ejemplo de uso
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python port_scanner.py <target> [quick|common|full]")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else 'quick'
    
    print(f"Escaneando {target}...")
    result = scan_target(target, scan_type)
    
    print(f"\n=== Resultados del Escaneo ===")
    print(f"Target: {result['target']}")
    print(f"Puertos escaneados: {result['total_ports_scanned']}")
    print(f"Puertos abiertos: {result['open_ports_count']}")
    print(f"Duración: {result['duration_seconds']}s")
    
    if result['open_ports']:
        print(f"\n=== Puertos Abiertos ===")
        for port_info in result['open_ports']:
            print(f"  {port_info['port']}/tcp - {port_info['service']} [{port_info['risk_level']}]")
            if port_info['banner']:
                print(f"    Banner: {port_info['banner'][:100]}")
    
    if result['recommendations']:
        print(f"\n=== Recomendaciones ===")
        for rec in result['recommendations']:
            print(f"  • {rec}")