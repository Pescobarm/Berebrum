"""
Berebrum - DNS Information Gatherer
Recopilación de registros DNS y análisis de configuración
"""

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import socket
from typing import Dict, List, Optional
from datetime import datetime


class DNSInformationGatherer:
    """
    Recopilador de información DNS
    """

    # Tipos de registros DNS a consultar
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"]

    # Servicios SRV comunes
    COMMON_SRV_RECORDS = [
        "_http._tcp",
        "_https._tcp",
        "_ftp._tcp",
        "_ssh._tcp",
        "_smtp._tcp",
        "_pop3._tcp",
        "_imap._tcp",
        "_ldap._tcp",
        "_kerberos._tcp",
        "_xmpp-client._tcp",
    ]

    def __init__(self, timeout: float = 3.0, nameservers: Optional[List[str]] = None):
        """
        Inicializar recopilador DNS

        Args:
            timeout: Timeout por consulta
            nameservers: Servidores DNS personalizados
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        if nameservers:
            self.resolver.nameservers = nameservers

    def gather_all(self, domain: str) -> Dict[str, any]:
        """
        Recopilar toda la información DNS disponible

        Args:
            domain: Dominio a analizar

        Returns:
            Información DNS completa
        """
        results = {
            "domain": domain,
            "records": {},
            "nameservers": [],
            "mail_servers": [],
            "txt_records": {
                "spf": None,
                "dmarc": None,
                "dkim": [],
                "other": [],
            },  # Inicializar como dict vacío
            "srv_records": [],
            "zone_transfer": None,
            "dnssec_enabled": False,
            "risk_analysis": {},
            "timestamp": datetime.now().isoformat(),
        }

        # Obtener registros por tipo
        for record_type in self.RECORD_TYPES:
            records = self._query_record_type(domain, record_type)
            if records:
                results["records"][record_type] = records

        # Procesar nameservers
        if "NS" in results["records"]:
            results["nameservers"] = results["records"]["NS"]

        # Procesar mail servers
        if "MX" in results["records"]:
            results["mail_servers"] = results["records"]["MX"]

        # Procesar registros TXT (buscar SPF, DKIM, DMARC)
        if "TXT" in results["records"]:
            results["txt_records"] = self._parse_txt_records(results["records"]["TXT"])

        # Buscar registros SRV
        results["srv_records"] = self._query_srv_records(domain)

        # Intentar zone transfer
        if results["nameservers"]:
            results["zone_transfer"] = self._attempt_zone_transfer(
                domain, results["nameservers"]
            )

        # Verificar DNSSEC
        results["dnssec_enabled"] = self._check_dnssec(domain)

        # Análisis de riesgos
        results["risk_analysis"] = self._analyze_risks(results)

        # Recomendaciones
        results["recommendations"] = self._generate_recommendations(results)

        return results

    def _query_record_type(self, domain: str, record_type: str) -> Optional[List[str]]:
        """
        Consultar un tipo específico de registro DNS
        """
        try:
            answers = self.resolver.resolve(domain, record_type)

            results = []
            for rdata in answers:
                if record_type == "MX":
                    results.append(
                        {"priority": rdata.preference, "server": str(rdata.exchange)}
                    )
                elif record_type == "SOA":
                    results.append(
                        {
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum,
                        }
                    )
                else:
                    results.append(str(rdata))

            return results if results else None

        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except Exception as e:
            return None

    def _parse_txt_records(self, txt_records: List[str]) -> Dict[str, any]:
        """
        Parsear registros TXT para identificar SPF, DKIM, DMARC
        """
        parsed = {"spf": None, "dmarc": None, "dkim": [], "other": []}

        for record in txt_records:
            record_str = str(record).strip('"')

            if record_str.startswith("v=spf1"):
                parsed["spf"] = record_str
            elif record_str.startswith("v=DMARC1"):
                parsed["dmarc"] = record_str
            elif "dkim" in record_str.lower():
                parsed["dkim"].append(record_str)
            else:
                parsed["other"].append(record_str)

        return parsed

    def _query_srv_records(self, domain: str) -> List[Dict]:
        """
        Consultar registros SRV comunes
        """
        srv_records = []

        for service in self.COMMON_SRV_RECORDS:
            full_name = f"{service}.{domain}"
            try:
                answers = self.resolver.resolve(full_name, "SRV")
                for rdata in answers:
                    srv_records.append(
                        {
                            "service": service,
                            "priority": rdata.priority,
                            "weight": rdata.weight,
                            "port": rdata.port,
                            "target": str(rdata.target),
                        }
                    )
            except:
                pass

        return srv_records

    def _attempt_zone_transfer(
        self, domain: str, nameservers: List[str]
    ) -> Dict[str, any]:
        """
        Intentar zone transfer (AXFR)
        """
        result = {
            "vulnerable": False,
            "nameservers_tested": [],
            "transferred_records": [],
        }

        for ns in nameservers[:3]:  # Probar solo los primeros 3 NS
            try:
                # Resolver la IP del nameserver
                ns_ip = socket.gethostbyname(ns.rstrip("."))
                result["nameservers_tested"].append({"ns": ns, "ip": ns_ip})

                # Intentar zone transfer
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=self.timeout)
                )

                # Si llegamos aquí, el zone transfer fue exitoso
                result["vulnerable"] = True
                result["transferred_records"] = [
                    str(name) for name in zone.nodes.keys()
                ][
                    :50
                ]  # Limitar a 50 registros

                break  # Salir si encontramos un NS vulnerable

            except dns.exception.FormError:
                continue
            except dns.query.TransferError:
                continue
            except socket.gaierror:
                continue
            except Exception as e:
                continue

        return result

    def _check_dnssec(self, domain: str) -> bool:
        """
        Verificar si DNSSEC está habilitado
        """
        try:
            # Intentar obtener registros DNSKEY
            answers = self.resolver.resolve(domain, "DNSKEY")
            return len(answers) > 0
        except:
            return False

    def _analyze_risks(self, results: Dict) -> Dict[str, any]:
        """
        Analizar riesgos de configuración DNS
        """
        risks = {"critical": [], "high": [], "medium": [], "low": []}

        # Zone transfer vulnerable
        if results["zone_transfer"] and results["zone_transfer"]["vulnerable"]:
            risks["critical"].append(
                {
                    "issue": "Zone Transfer Enabled",
                    "description": "Zone transfer (AXFR) está habilitado, permitiendo obtener todos los registros DNS",
                    "affected_ns": results["zone_transfer"]["nameservers_tested"],
                }
            )

        # SPF no configurado
        if not results["txt_records"].get("spf"):
            risks["high"].append(
                {
                    "issue": "Missing SPF Record",
                    "description": "No se encontró registro SPF. Los correos pueden ser fácilmente suplantados.",
                }
            )

        # DMARC no configurado
        if not results["txt_records"].get("dmarc"):
            risks["high"].append(
                {
                    "issue": "Missing DMARC Record",
                    "description": "No se encontró registro DMARC. No hay política de manejo de correos falsos.",
                }
            )

        # DNSSEC no habilitado
        if not results["dnssec_enabled"]:
            risks["medium"].append(
                {
                    "issue": "DNSSEC Not Enabled",
                    "description": "DNSSEC no está habilitado. El dominio es vulnerable a DNS spoofing.",
                }
            )

        # Wildcard DNS
        wildcard_test = self._query_record_type(
            f"berebrum-nonexistent-test-{datetime.now().timestamp()}.{results['domain']}",
            "A",
        )
        if wildcard_test:
            risks["low"].append(
                {
                    "issue": "Wildcard DNS Enabled",
                    "description": "DNS wildcard está habilitado. Todos los subdominios resuelven a la misma IP.",
                }
            )

        return risks

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """
        Generar recomendaciones de seguridad
        """
        recommendations = []
        risks = results["risk_analysis"]

        if risks["critical"]:
            recommendations.append(
                "CRÍTICO: Deshabilitar zone transfer (AXFR) en todos los nameservers inmediatamente. "
                "Configurar ACLs para permitir solo transferencias autorizadas."
            )

        if any("SPF" in str(r) for r in risks["high"]):
            recommendations.append(
                "Configurar registro SPF para prevenir suplantación de correos. "
                "Ejemplo: v=spf1 mx -all"
            )

        if any("DMARC" in str(r) for r in risks["high"]):
            recommendations.append(
                "Configurar registro DMARC para política de correos. "
                "Ejemplo: v=DMARC1; p=quarantine; rua=mailto:admin@example.com"
            )

        if any("DNSSEC" in str(r) for r in risks["medium"]):
            recommendations.append(
                "Habilitar DNSSEC para proteger contra DNS spoofing y cache poisoning."
            )

        if not recommendations:
            recommendations.append(
                "La configuración DNS es buena. Sin problemas críticos detectados."
            )

        return recommendations


def gather_dns_info(domain: str) -> Dict[str, any]:
    """
    Función de utilidad para recopilar información DNS
    SIEMPRE devuelve un diccionario, nunca una lista o None
    """
    # Estructura base que siempre se devuelve
    base_result = {
        "domain": domain,
        "records": {},
        "nameservers": [],
        "mail_servers": [],
        "txt_records": [],
        "srv_records": [],
        "zone_transfer": None,
        "dnssec_enabled": False,
        "risk_analysis": {},
        "recommendations": [],
        "timestamp": datetime.now().isoformat(),
    }

    try:
        gatherer = DNSInformationGatherer()
        result = gatherer.gather_all(domain)

        # Validación crítica: asegurar que result es un dict
        if not isinstance(result, dict):
            base_result["error"] = (
                f"La herramienta devolvió tipo inválido: {type(result).__name__}"
            )
            return base_result

        # Si es un dict válido, lo devolvemos
        return result

    except dns.resolver.NXDOMAIN:
        base_result["error"] = "El dominio no existe (NXDOMAIN)"
        return base_result
    except dns.resolver.NoNameservers:
        base_result["error"] = "No se encontraron servidores DNS"
        return base_result
    except dns.resolver.Timeout:
        base_result["error"] = "Timeout en consulta DNS"
        return base_result
    except Exception as e:
        # Capturar cualquier otro error y devolver estructura válida
        base_result["error"] = f"{type(e).__name__}: {str(e)}"
        return base_result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python dns_gatherer.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    print(f"Recopilando información DNS de {domain}...")
    result = gather_dns_info(domain)

    print(f"\n=== Información DNS ===")
    print(f"Dominio: {result['domain']}")

    # Registros A/AAAA
    if "A" in result["records"]:
        print(f"\nRegistros A:")
        for ip in result["records"]["A"]:
            print(f"  {ip}")

    # Nameservers
    if result["nameservers"]:
        print(f"\nNameservers:")
        for ns in result["nameservers"]:
            print(f"  {ns}")

    # Mail servers
    if result["mail_servers"]:
        print(f"\nMail Servers:")
        for mx in result["mail_servers"]:
            print(f"  [{mx['priority']}] {mx['server']}")

    # SPF/DMARC/DKIM
    print(f"\nEmail Security:")
    print(f"  SPF: {'✓ Configured' if result['txt_records']['spf'] else '✗ Missing'}")
    print(
        f"  DMARC: {'✓ Configured' if result['txt_records']['dmarc'] else '✗ Missing'}"
    )
    print(f"  DNSSEC: {'✓ Enabled' if result['dnssec_enabled'] else '✗ Disabled'}")

    # Zone Transfer
    if result["zone_transfer"]:
        if result["zone_transfer"]["vulnerable"]:
            print(f"\n🔴 CRÍTICO: Zone Transfer Vulnerable!")
            print(
                f"  Records transferred: {len(result['zone_transfer']['transferred_records'])}"
            )
        else:
            print(f"\n✓ Zone Transfer: Protected")

    # Riesgos
    risks = result["risk_analysis"]
    total_risks = len(risks["critical"]) + len(risks["high"]) + len(risks["medium"])

    if total_risks > 0:
        print(f"\n=== Riesgos Detectados ({total_risks}) ===")

        for risk in risks["critical"]:
            print(f"\n🔴 CRÍTICO: {risk['issue']}")
            print(f"  {risk['description']}")

        for risk in risks["high"]:
            print(f"\n🟠 ALTO: {risk['issue']}")
            print(f"  {risk['description']}")

        for risk in risks["medium"]:
            print(f"\n🟡 MEDIO: {risk['issue']}")
            print(f"  {risk['description']}")

    # Recomendaciones
    if result["recommendations"]:
        print(f"\n=== Recomendaciones ===")
        for rec in result["recommendations"]:
            print(f"  • {rec}")
