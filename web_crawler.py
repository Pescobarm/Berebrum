"""
Web Crawler v1.0
Encuentra URLs con parámetros para testing automático
Módulo reutilizable para todos los scanners
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Set
import re
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebCrawler:
    """
    Web Crawler para encontrar URLs con parámetros
    """

    def __init__(
        self,
        max_pages: int = 50,
        max_depth: int = 3,
        timeout: float = 5.0,
        follow_external: bool = False,
    ):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.follow_external = follow_external

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        self.visited_urls: Set[str] = set()
        self.urls_with_params: List[Dict] = []
        self.base_domain = ""

    def crawl(self, start_url: str) -> List[Dict]:
        """
        Crawlea un sitio y encuentra URLs con parámetros

        Args:
            start_url: URL inicial (puede ser solo dominio o URL completa)

        Returns:
            Lista de URLs con parámetros:
            [
                {
                    'url': 'http://site.com/page.php?id=1',
                    'params': ['id'],
                    'method': 'GET'
                }
            ]
        """
        # Normalizar URL
        if not start_url.startswith(("http://", "https://")):
            start_url = "http://" + start_url

        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc

        print(f"[*] Web Crawler v1.0")
        print(f"[*] Target: {start_url}")
        print(f"[*] Max pages: {self.max_pages}")
        print(f"[*] Max depth: {self.max_depth}")
        print()

        # Si la URL ya tiene parámetros, agregarla
        if parsed.query:
            params = list(parse_qs(parsed.query).keys())
            self.urls_with_params.append(
                {"url": start_url, "params": params, "method": "GET"}
            )
            print(f"[✓] URL inicial tiene parámetros: {', '.join(params)}")

        # Empezar crawling desde la raíz
        base_url = f"{parsed.scheme}://{parsed.netloc}/"

        self._crawl_recursive(base_url, depth=0)

        print(f"\n[*] Crawling completado")
        print(f"[*] Páginas visitadas: {len(self.visited_urls)}")
        print(f"[*] URLs con parámetros encontradas: {len(self.urls_with_params)}")

        return self.urls_with_params

    def _crawl_recursive(self, url: str, depth: int):
        """Crawlea recursivamente una URL"""

        # Límites
        if depth > self.max_depth:
            return

        if len(self.visited_urls) >= self.max_pages:
            return

        if url in self.visited_urls:
            return

        # Filtrar por dominio
        parsed = urlparse(url)
        if not self.follow_external and parsed.netloc != self.base_domain:
            return

        # Visitar
        self.visited_urls.add(url)

        try:
            print(f"[*] Crawling [{depth}]: {url[:60]}...")

            response = self.session.get(url, timeout=self.timeout, verify=False)

            if response.status_code != 200:
                return

            # Buscar enlaces y forms
            self._extract_links(response.text, url, depth)
            self._extract_forms(response.text, url)

            time.sleep(0.1)  # Rate limiting

        except Exception as e:
            print(f"    [!] Error: {str(e)[:50]}")
            return

    def _extract_links(self, html: str, base_url: str, depth: int):
        """Extrae enlaces del HTML"""

        try:
            soup = BeautifulSoup(html, "html.parser")

            for link in soup.find_all("a", href=True):
                href = link["href"]

                # Construir URL absoluta
                absolute_url = urljoin(base_url, href)

                # Parsear
                parsed = urlparse(absolute_url)

                # Filtrar URLs no HTTP
                if parsed.scheme not in ["http", "https"]:
                    continue

                # Si tiene parámetros, agregarla
                if parsed.query:
                    params = list(parse_qs(parsed.query).keys())

                    # Evitar duplicados
                    url_without_values = self._normalize_url(absolute_url)

                    if not any(
                        u["url_normalized"] == url_without_values
                        for u in self.urls_with_params
                    ):
                        self.urls_with_params.append(
                            {
                                "url": absolute_url,
                                "url_normalized": url_without_values,
                                "params": params,
                                "method": "GET",
                            }
                        )

                        print(f"  [✓] Parámetros encontrados: {', '.join(params)}")

                # Crawlear recursivamente
                self._crawl_recursive(absolute_url, depth + 1)

        except Exception as e:
            return

    def _extract_forms(self, html: str, base_url: str):
        """Extrae formularios del HTML"""

        try:
            soup = BeautifulSoup(html, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()

                # Construir URL del form
                form_url = urljoin(base_url, action) if action else base_url

                # Extraer inputs
                params = []
                for input_tag in form.find_all(["input", "select", "textarea"]):
                    name = input_tag.get("name")
                    if name:
                        params.append(name)

                if params:
                    # Normalizar URL
                    url_normalized = self._normalize_url(form_url)

                    if not any(
                        u["url_normalized"] == url_normalized
                        for u in self.urls_with_params
                    ):
                        self.urls_with_params.append(
                            {
                                "url": form_url,
                                "url_normalized": url_normalized,
                                "params": params,
                                "method": method,
                            }
                        )

                        print(f"  [✓] Form encontrado ({method}): {', '.join(params)}")

        except Exception as e:
            return

    def _normalize_url(self, url: str) -> str:
        """
        Normaliza URL removiendo valores de parámetros
        Para evitar duplicados como ?id=1 y ?id=2
        """
        parsed = urlparse(url)

        if not parsed.query:
            return url

        # Extraer nombres de parámetros (sin valores)
        params = parse_qs(parsed.query)
        param_names = sorted(params.keys())

        # Reconstruir query string solo con nombres
        normalized_query = "&".join([f"{p}=" for p in param_names])

        # Reconstruir URL
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                normalized_query,
                "",
            )
        )


def find_urls_with_parameters(
    domain: str,
    max_pages: int = 50,
    max_depth: int = 3,
    timeout: float = 5.0,
) -> List[Dict]:
    """
    Función wrapper para usar en scanners

    Args:
        domain: Dominio o URL a crawlear
        max_pages: Máximo de páginas a visitar
        max_depth: Profundidad máxima de crawling
        timeout: Timeout por request

    Returns:
        Lista de URLs con parámetros
    """
    crawler = WebCrawler(
        max_pages=max_pages, max_depth=max_depth, timeout=timeout, follow_external=False
    )

    return crawler.crawl(domain)


# Ejemplo de uso
if __name__ == "__main__":
    # Test
    urls = find_urls_with_parameters("testphp.vulnweb.com", max_pages=20, max_depth=2)

    print(f"\n{'='*60}")
    print(f"RESULTADOS")
    print(f"{'='*60}\n")

    for i, url_info in enumerate(urls, 1):
        print(f"{i}. {url_info['url']}")
        print(f"   Parámetros: {', '.join(url_info['params'])}")
        print(f"   Método: {url_info['method']}")
        print()
