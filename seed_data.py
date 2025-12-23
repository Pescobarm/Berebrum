from database.session import SessionLocal, engine
from database.models import Base, Project, Finding, AttackFlow
from datetime import datetime, timedelta
import random

# Reiniciar DB
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
session = SessionLocal()

def create_fake_data():
    print("🌱 Sembrando datos FORENSES reales...")
    
    # 1. Proyecto
    p = Project(name="FinTech Corp Audit", scope_cidrs="192.168.1.10, fintech.corp")
    session.add(p)
    session.commit()

    # 2. Evidencias Realistas (HTTP Dumps)
    
    evidencia_sqli = """GET /api/v1/users?id=1' OR 1=1-- HTTP/1.1
Host: fintech.corp
User-Agent: sqlmap/1.5.11
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json
{
  "id": 1,
  "username": "admin",
  "password_hash": "e10adc3949ba59abbe56e057f20f883e"
}
"""

    evidencia_xss = """POST /comments/new HTTP/1.1
Host: fintech.corp
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

comment=<script>alert(document.cookie)</script>&user_id=101

HTTP/1.1 200 OK
Set-Cookie: SESSIONID=af123981203912; Secure; HttpOnly
"""

    evidencia_rce = """GET /admin/system.php?cmd=cat+/etc/passwd HTTP/1.1
Host: 192.168.1.10
Cookie: admin=true

HTTP/1.1 200 OK
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
"""

    # Insertar Hallazgos
    findings_data = [
        ("SQL Injection (Blind)", "Critical", "T1190", "fintech.corp/api/v1/users", evidencia_sqli),
        ("Stored XSS", "High", "T1059", "fintech.corp/comments", evidencia_xss),
        ("RCE via Command Injection", "Critical", "T1210", "192.168.1.10", evidencia_rce),
        ("Information Disclosure", "Low", "T1592", "fintech.corp/robots.txt", "GET /robots.txt... Disallow: /admin_backup")
    ]

    for v_name, severity, mitre, target, evidence in findings_data:
        f = Finding(
            project_id=p.id,
            vulnerability_name=v_name,
            severity=severity,
            mitre_id=mitre,
            target=target,
            evidence=evidence  # Aquí va el dump HTTP
        )
        session.add(f)
    
    # 3. Historial de Operaciones (Attack Flow)
    tools = ["Nmap Scanner", "SQLiScanner", "DirBuster", "Metasploit"]
    targets = ["192.168.1.10", "192.168.1.15", "fintech.corp", "db.fintech.corp"]
    
    now = datetime.utcnow()
    for i in range(25):
        t_delta = timedelta(hours=random.randint(1, 48))
        target_sel = random.choice(targets)
        af = AttackFlow(
            project_id=p.id,
            timestamp=now - t_delta,
            tool_used=random.choice(tools),
            target=target_sel,
            status=random.choice(["SUCCESS", "FAILED", "BLOCKED"]),
            output_summary=f"Scan completed on {target_sel}. Ports 80, 443 open.",
            command_executed=f"nmap -sV -p- {target_sel}"
        )
        session.add(af)

    session.commit()
    print("✅ Datos generados. ¡Abre el Dashboard!")

if __name__ == "__main__":
    create_fake_data()