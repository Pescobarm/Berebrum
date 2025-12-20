"""
NeuroStrike Hub - Sistema de Modos de Escaneo
Gestión de perfiles stealth, normal y aggressive para todas las herramientas
"""

from typing import Dict, Any
from dataclasses import dataclass
import random
import time


@dataclass
class ScanMode:
    """Configuración de modo de escaneo"""

    name: str
    description: str
    delay_between_requests: float
    max_threads: int
    timeout: int
    randomize_user_agent: bool
    use_evasion: bool
    scan_intensity: str
    rate_limit: int  # requests per second


class ScanModeManager:
    """
    Gestor de modos de escaneo

    Modos disponibles:
    - stealth: Evita detección, muy lento
    - normal: Balance entre velocidad y sigilo
    - aggressive: Máxima velocidad, alta probabilidad de detección
    """

    MODES = {
        "stealth": ScanMode(
            name="🕵️  Stealth Mode (Silencioso)",
            description="Evita detección por IDS/IPS. Más lento pero sigiloso.",
            delay_between_requests=3.0,  # 3 segundos entre requests
            max_threads=1,  # Single thread
            timeout=30,  # 30 segundos timeout
            randomize_user_agent=True,
            use_evasion=True,
            scan_intensity="low",
            rate_limit=1,  # 1 request/segundo
        ),
        "normal": ScanMode(
            name="⚡ Normal Mode (Balanceado)",
            description="Balance entre velocidad y sigilo. Recomendado para uso general.",
            delay_between_requests=0.5,  # 500ms entre requests
            max_threads=5,  # 5 threads paralelos
            timeout=10,  # 10 segundos timeout
            randomize_user_agent=True,
            use_evasion=False,
            scan_intensity="medium",
            rate_limit=10,  # 10 requests/segundo
        ),
        "aggressive": ScanMode(
            name="🔥 Aggressive Mode (Rápido)",
            description="Máxima velocidad. Alta probabilidad de detección.",
            delay_between_requests=0.0,  # Sin delay
            max_threads=20,  # 20 threads paralelos
            timeout=3,  # 3 segundos timeout
            randomize_user_agent=False,
            use_evasion=False,
            scan_intensity="high",
            rate_limit=100,  # 100 requests/segundo
        ),
    }

    # User-Agents para rotación (evasión)
    USER_AGENTS = [
        # Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        # Mobile
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    ]

    def __init__(self, mode: str = "normal"):
        """
        Inicializar gestor de modos

        Args:
            mode: 'stealth', 'normal' o 'aggressive'
        """
        if mode not in self.MODES:
            raise ValueError(
                f"Modo inválido: {mode}. Use: stealth, normal o aggressive"
            )

        self.current_mode = mode
        self.config = self.MODES[mode]
        self._request_count = 0
        self._last_request_time = 0

    @classmethod
    def get_mode_config(cls, mode: str) -> ScanMode:
        """Obtener configuración de un modo específico"""
        if mode not in cls.MODES:
            return cls.MODES["normal"]
        return cls.MODES[mode]

    @classmethod
    def list_modes(cls) -> Dict[str, Dict[str, Any]]:
        """Listar todos los modos disponibles con sus configuraciones"""
        return {
            mode_name: {
                "name": mode.name,
                "description": mode.description,
                "delay": mode.delay_between_requests,
                "threads": mode.max_threads,
                "timeout": mode.timeout,
                "intensity": mode.scan_intensity,
            }
            for mode_name, mode in cls.MODES.items()
        }

    def get_user_agent(self) -> str:
        """
        Obtener User-Agent

        Returns:
            User-Agent (random si está habilitado, estático si no)
        """
        if self.config.randomize_user_agent:
            return random.choice(self.USER_AGENTS)
        return self.USER_AGENTS[0]  # Chrome estático

    def apply_delay(self):
        """Aplicar delay entre requests según el modo"""
        if self.config.delay_between_requests > 0:
            time.sleep(self.config.delay_between_requests)

    def apply_rate_limit(self):
        """
        Aplicar rate limiting
        Evita exceder el límite de requests por segundo
        """
        current_time = time.time()
        time_since_last = current_time - self._last_request_time

        if time_since_last < (1.0 / self.config.rate_limit):
            # Esperar para no exceder el rate limit
            sleep_time = (1.0 / self.config.rate_limit) - time_since_last
            time.sleep(sleep_time)

        self._last_request_time = time.time()
        self._request_count += 1

    def get_timeout(self) -> int:
        """Obtener timeout configurado"""
        return self.config.timeout

    def get_max_threads(self) -> int:
        """Obtener número máximo de threads"""
        return self.config.max_threads

    def should_use_evasion(self) -> bool:
        """Determinar si usar técnicas de evasión"""
        return self.config.use_evasion

    def get_scan_intensity(self) -> str:
        """Obtener intensidad del escaneo"""
        return self.config.scan_intensity

    def get_summary(self) -> Dict[str, Any]:
        """Obtener resumen del modo actual"""
        return {
            "mode": self.current_mode,
            "name": self.config.name,
            "description": self.config.description,
            "settings": {
                "delay": self.config.delay_between_requests,
                "max_threads": self.config.max_threads,
                "timeout": self.config.timeout,
                "rate_limit": self.config.rate_limit,
                "evasion": self.config.use_evasion,
                "intensity": self.config.scan_intensity,
            },
            "requests_made": self._request_count,
        }


class EvasionTechniques:
    """
    Técnicas de evasión para modo stealth
    """

    @staticmethod
    def randomize_case(payload: str, chance: float = 0.3) -> str:
        """
        Randomizar mayúsculas/minúsculas en payload

        Args:
            payload: Payload original
            chance: Probabilidad de cambiar cada carácter (0.0 - 1.0)

        Returns:
            Payload con case randomizado
        """
        result = []
        for char in payload:
            if random.random() < chance and char.isalpha():
                result.append(char.swapcase())
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def add_null_bytes(payload: str) -> str:
        """
        Agregar null bytes para evadir filtros

        Args:
            payload: Payload original

        Returns:
            Payload con null bytes
        """
        # Agregar %00 en posiciones aleatorias
        positions = random.sample(range(len(payload)), min(3, len(payload) // 4))
        result = list(payload)

        for pos in sorted(positions, reverse=True):
            result.insert(pos, "%00")

        return "".join(result)

    @staticmethod
    def encode_payload(payload: str, encoding: str = "url") -> str:
        """
        Codificar payload para evasión

        Args:
            payload: Payload original
            encoding: Tipo de encoding ('url', 'double_url', 'unicode')

        Returns:
            Payload codificado
        """
        if encoding == "url":
            # URL encoding simple
            return "".join(f"%{ord(c):02x}" if not c.isalnum() else c for c in payload)

        elif encoding == "double_url":
            # Double URL encoding
            first_encode = "".join(f"%{ord(c):02x}" for c in payload)
            return "".join(f"%{ord(c):02x}" for c in first_encode)

        elif encoding == "unicode":
            # Unicode encoding
            return "".join(f"\\u{ord(c):04x}" for c in payload)

        return payload

    @staticmethod
    def fragment_payload(payload: str) -> str:
        """
        Fragmentar payload con comentarios SQL

        Args:
            payload: Payload SQL

        Returns:
            Payload fragmentado
        """
        # Insertar comentarios SQL en posiciones aleatorias
        fragments = []
        words = payload.split()

        for i, word in enumerate(words):
            fragments.append(word)
            if i < len(words) - 1 and random.random() < 0.5:
                fragments.append("/**/")  # Comentario SQL vacío

        return " ".join(fragments)


# Función de utilidad para crear gestor de modos
def create_scan_mode(mode: str = "normal") -> ScanModeManager:
    """
    Crear gestor de modo de escaneo

    Args:
        mode: 'stealth', 'normal' o 'aggressive'

    Returns:
        ScanModeManager configurado
    """
    return ScanModeManager(mode)


if __name__ == "__main__":
    # Test del sistema de modos
    print("=== NEUROSTRIKE HUB - Modos de Escaneo ===\n")

    # Listar modos
    print("Modos disponibles:")
    for mode_name, config in ScanModeManager.list_modes().items():
        print(f"\n{mode_name.upper()}:")
        print(f"  Nombre: {config['name']}")
        print(f"  Descripción: {config['description']}")
        print(f"  Delay: {config['delay']}s")
        print(f"  Threads: {config['threads']}")
        print(f"  Timeout: {config['timeout']}s")
        print(f"  Intensidad: {config['intensity']}")

    # Test de evasión
    print("\n=== Test de Técnicas de Evasión ===\n")

    payload = "' OR 1=1--"
    print(f"Payload original: {payload}")
    print(f"Case randomizado: {EvasionTechniques.randomize_case(payload)}")
    print(f"Con null bytes: {EvasionTechniques.add_null_bytes(payload)}")
    print(f"URL encoded: {EvasionTechniques.encode_payload(payload, 'url')}")
    print(f"Fragmentado: {EvasionTechniques.fragment_payload(payload)}")
