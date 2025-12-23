import ipaddress
import socket
from urllib.parse import urlparse
import logging

# Configuración de log simple para el guardián
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ScopeGuardian")


class ScopeGuardian:
    def __init__(self, scope_definitions):
        """
        scope_definitions: Lista de strings.
        Ejemplo: ['192.168.1.0/24', 'target.com', '10.0.0.5']
        """
        self.allowed_networks = []
        self.allowed_domains = []
        self._parse_scope(scope_definitions)

    def _parse_scope(self, scopes):
        """Clasifica los inputs en Redes IP o Dominios"""
        for item in scopes:
            item = item.strip()
            try:
                # Intentamos tratarlo como una red IP (CIDR o IP sola)
                network = ipaddress.ip_network(item, strict=False)
                self.allowed_networks.append(network)
                logger.info(f"[Scope] Red añadida: {network}")
            except ValueError:
                # Si falla, asumimos que es un dominio
                self.allowed_domains.append(item)
                logger.info(f"[Scope] Dominio añadido: {item}")

    def validate_target(self, target):
        """
        Valida si un target (IP o URL) está dentro del Scope permitido.
        Retorna True (Permitido) o False (Bloqueado).
        """
        original_target = target
        try:
            # 1. Limpieza: Si viene con http:// o https://, extraemos el hostname
            if "://" in target:
                target = urlparse(target).hostname

            # Si target quedó vacío tras parsear
            if not target:
                logger.warning(f"[BLOCK] Target inválido o vacío: {original_target}")
                return False

            # 2. Resolución DNS: Convertimos dominio a IP para verificar contra rangos CIDR
            # Esto evita bypasses usando dominios que apuntan a IPs internas prohibidas
            try:
                target_ip = ipaddress.ip_address(socket.gethostbyname(target))
            except socket.gaierror:
                # Si no resuelve DNS, no podemos validarlo por IP, pero validamos por nombre
                target_ip = None
                logger.warning(
                    f"[Scope] No se pudo resolver IP para {target}. Verificando solo por dominio."
                )

            # 3. Verificación de IP contra Redes (Si tenemos IP)
            if target_ip:
                for net in self.allowed_networks:
                    if target_ip in net:
                        logger.info(
                            f"[ALLOW] {target} ({target_ip}) está en rango {net}"
                        )
                        return True

            # 4. Verificación de Dominio (Texto)
            # Aceptamos el dominio exacto o subdominios (ej: api.target.com)
            for domain in self.allowed_domains:
                if target == domain or target.endswith("." + domain):
                    logger.info(
                        f"[ALLOW] {target} coincide con scope de dominio {domain}"
                    )
                    return True

            # Si llegamos aquí, nada coincidió.
            logger.warning(
                f"[BLOCK] Intento de acceso fuera de Scope: {original_target} ({target_ip})"
            )
            return False

        except Exception as e:
            logger.error(
                f"[ERROR] Fallo en validación de scope para {original_target}: {e}"
            )
            return False
