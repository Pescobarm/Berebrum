"""
NeuroStrike Hub - Tool Registry
Registro centralizado de todas las herramientas disponibles
"""

TOOLS = {
    # === RECONNAISSANCE ===
    'Port Scanner (Quick)': {
        'module': 'tools.recon.port_scanner',
        'function': 'scan_target',
        'category': 'reconnaissance',
        'mitre_id': 'T1046',
        'description': 'Escaneo rápido de puertos comunes',
        'scan_mode_support': True
    },
    'Service Banner Grabber': {
        'module': 'tools.recon.banner_grabber',
        'function': 'grab_banners',
        'category': 'reconnaissance',
        'mitre_id': 'T1046',
        'description': 'Captura de banners de servicios',
        'scan_mode_support': True
    },
    'Subdomain Enumerator': {
        'module': 'tools.recon.subdomain_enum',
        'function': 'enumerate_subdomains',
        'category': 'reconnaissance',
        'mitre_id': 'T1595',
        'description': 'Enumeración de subdominios',
        'scan_mode_support': True
    },
    'DNS Information Gatherer': {
        'module': 'tools.recon.dns_gatherer',
        'function': 'gather_dns_info',
        'category': 'reconnaissance',
        'mitre_id': 'T1590',
        'description': 'Recopilación de registros DNS',
        'scan_mode_support': False
    },
    'SSL/TLS Analyzer': {
        'module': 'tools.recon.ssl_analyzer',
        'function': 'analyze_ssl',
        'category': 'reconnaissance',
        'mitre_id': 'T1040',
        'description': 'Análisis de certificados SSL/TLS',
        'scan_mode_support': False
    },
    'HTTP Header Analyzer': {
        'module': 'tools.recon.header_analyzer',
        'function': 'analyze_headers',
        'category': 'reconnaissance',
        'mitre_id': 'T1592',
        'description': 'Análisis de headers HTTP de seguridad',
        'scan_mode_support': False
    },
    'Web Directory Scanner': {
        'module': 'tools.recon.web_dir_scanner',
        'function': 'scan_web_directories',
        'category': 'reconnaissance',
        'mitre_id': 'T1083',
        'description': 'Descubrimiento de directorios web',
        'scan_mode_support': True
    },
    'Vulnerability Scanner': {
        'module': 'tools.recon.vuln_scanner',
        'function': 'scan_vulnerabilities',
        'category': 'reconnaissance',
        'mitre_id': 'T1190',
        'description': 'Escaneo de vulnerabilidades web',
        'scan_mode_support': True
    },
    
    # === EXPLOITATION (OWASP) ===
    'SQL Injection Scanner': {
        'module': 'tools.exploit.sqli_scanner',
        'function': 'scan_sqli',
        'category': 'exploitation',
        'mitre_id': 'T1190',
        'owasp': 'A03:2021 - Injection',
        'description': 'Detección de vulnerabilidades SQL Injection',
        'scan_mode_support': True
    },
    'XSS Detector': {
        'module': 'tools.exploit.xss_detector',
        'function': 'scan_xss',
        'category': 'exploitation',
        'mitre_id': 'T1189',
        'owasp': 'A03:2021 - Injection',
        'description': 'Detección de Cross-Site Scripting (XSS)',
        'scan_mode_support': True
    },
    'CSRF Tester': {
        'module': 'tools.exploit.csrf_tester',
        'function': 'scan_csrf',
        'category': 'exploitation',
        'mitre_id': 'T1184',
        'owasp': 'A01:2021 - Broken Access Control',
        'description': 'Verificación de protecciones CSRF',
        'scan_mode_support': True
    },
    
    # === BRUTE FORCE ===
    'SSH Brute Force': {
        'module': 'tools.brute_force.ssh_brute',
        'function': 'brute_force_ssh',
        'category': 'brute_force',
        'mitre_id': 'T1110.001',
        'description': 'Ataque de fuerza bruta contra SSH',
        'scan_mode_support': True
    }
}

# Categorías
CATEGORIES = {
    'reconnaissance': 'Reconocimiento',
    'exploitation': 'Explotación (OWASP)',
    'brute_force': 'Fuerza Bruta',
    'mobile': 'Mobile & App Security',
    'post_exploit': 'Post-Explotación'
}

def get_tools_by_category(category: str):
    """Obtener herramientas de una categoría"""
    return {
        name: config 
        for name, config in TOOLS.items() 
        if config.get('category') == category
    }

def get_all_categories():
    """Obtener todas las categorías con herramientas"""
    return {
        cat_id: {
            'name': cat_name,
            'tools': get_tools_by_category(cat_id),
            'count': len(get_tools_by_category(cat_id))
        }
        for cat_id, cat_name in CATEGORIES.items()
        if len(get_tools_by_category(cat_id)) > 0
    }
