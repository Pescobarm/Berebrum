"""
Berebrum Tools Package
Red Team tools collection
"""

# Importaciones individuales con manejo de errores robusto
__all__ = []

# Port Scanner
try:
    from .port_scanner import PortScanner
    __all__.append('PortScanner')
    try:
        from .port_scanner import scan_target
        __all__.append('scan_target')
    except (ImportError, AttributeError):
        pass
except Exception:
    PortScanner = None
    scan_target = None

# Banner Grabber
try:
    from .banner_grabber import BannerGrabber
    __all__.append('BannerGrabber')
    try:
        from .banner_grabber import grab_service_banner
        __all__.append('grab_service_banner')
    except (ImportError, AttributeError):
        pass
except Exception:
    BannerGrabber = None
    grab_service_banner = None

# Subdomain Enumerator - Requiere dnspython
try:
    import dns.resolver  # Verificar que dnspython funciona
    from .subdomain_enum import SubdomainEnumerator
    __all__.append('SubdomainEnumerator')
    try:
        from .subdomain_enum import enumerate_subdomains
        __all__.append('enumerate_subdomains')
    except (ImportError, AttributeError):
        pass
except Exception:
    SubdomainEnumerator = None
    enumerate_subdomains = None

# Web Directory Scanner
try:
    from .web_dir_scanner import WebDirectoryScanner
    __all__.append('WebDirectoryScanner')
    try:
        from .web_dir_scanner import scan_web_directories
        __all__.append('scan_web_directories')
    except (ImportError, AttributeError):
        pass
except Exception:
    WebDirectoryScanner = None
    scan_web_directories = None

# HTTP Header Analyzer
try:
    from .header_analyzer import HTTPHeaderAnalyzer
    __all__.append('HTTPHeaderAnalyzer')
    try:
        from .header_analyzer import analyze_headers
        __all__.append('analyze_headers')
    except (ImportError, AttributeError):
        pass
except Exception:
    HTTPHeaderAnalyzer = None
    analyze_headers = None

# DNS Information Gatherer - Requiere dnspython
try:
    import dns.resolver  # Verificar que dnspython funciona
    from .dns_gatherer import DNSInformationGatherer
    __all__.append('DNSInformationGatherer')
    try:
        from .dns_gatherer import gather_dns_info
        __all__.append('gather_dns_info')
    except (ImportError, AttributeError):
        pass
except Exception:
    DNSInformationGatherer = None
    gather_dns_info = None

# SSL/TLS Analyzer
try:
    from .ssl_analyzer import SSLAnalyzer
    __all__.append('SSLAnalyzer')
    try:
        from .ssl_analyzer import analyze_ssl
        __all__.append('analyze_ssl')
    except (ImportError, AttributeError):
        pass
except Exception:
    SSLAnalyzer = None
    analyze_ssl = None

# Vulnerability Scanner
try:
    from .vuln_scanner import VulnerabilityScanner
    __all__.append('VulnerabilityScanner')
    try:
        from .vuln_scanner import scan_vulnerabilities
        __all__.append('scan_vulnerabilities')
    except (ImportError, AttributeError):
        pass
except Exception:
    VulnerabilityScanner = None
    scan_vulnerabilities = None