# scripts/create-core.ps1
# Crea los archivos core del sistema Berebrum

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        📦 Creando archivos CORE de Berebrum              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ============== core/database.py ==============
Write-Host "[1/8] Creando core/database.py..." -ForegroundColor Yellow

$databaseContent = @'
"""
Berebrum - Database Models
Modelos SQLAlchemy con integración MITRE ATT&CK y CVSS
"""

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


class Project(Base):
    __tablename__ = 'projects'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    scope_ips = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default='active')
    
    logs = relationship("Log", back_populates="project")
    vulnerabilities = relationship("Vulnerability", back_populates="project")


class Log(Base):
    __tablename__ = 'logs'
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    tool_name = Column(String(100))
    tool_category = Column(String(50))
    target = Column(String(255))
    command = Column(Text)
    output = Column(Text)
    success = Column(Boolean, default=False)
    duration_seconds = Column(Float)
    mitre_technique_id = Column(String(20))
    mitre_technique_name = Column(String(200))
    mitre_tactic = Column(String(100))
    
    project = relationship("Project", back_populates="logs")


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    target = Column(String(255))
    port = Column(Integer)
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    severity = Column(String(20))
    mitre_technique_id = Column(String(20))
    mitre_technique_name = Column(String(200))
    cve_id = Column(String(50))
    proof_of_concept = Column(Text)
    
    project = relationship("Project", back_populates="vulnerabilities")


class DatabaseManager:
    def __init__(self, database_url="sqlite:///database/berebrum.db"):
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def init_db(self):
        Base.metadata.create_all(self.engine)
        print("✓ Base de datos inicializada")
    
    def get_session(self):
        return self.SessionLocal()
    
    def create_project(self, name, scope_ips, description=None):
        session = self.get_session()
        try:
            project = Project(name=name, scope_ips=scope_ips, description=description)
            session.add(project)
            session.commit()
            session.refresh(project)
            return project
        finally:
            session.close()
    
    def get_project(self, project_id):
        session = self.get_session()
        try:
            return session.query(Project).filter(Project.id == project_id).first()
        finally:
            session.close()
    
    def get_project_by_name(self, name):
        session = self.get_session()
        try:
            return session.query(Project).filter(Project.name == name).first()
        finally:
            session.close()
    
    def list_projects(self, status=None):
        session = self.get_session()
        try:
            query = session.query(Project)
            if status:
                query = query.filter(Project.status == status)
            return query.order_by(Project.created_at.desc()).all()
        finally:
            session.close()
    
    def create_log(self, project_id, tool_name, target, command, **kwargs):
        session = self.get_session()
        try:
            log = Log(
                project_id=project_id,
                tool_name=tool_name,
                target=target,
                command=command,
                **kwargs
            )
            session.add(log)
            session.commit()
            return log
        finally:
            session.close()
    
    def get_logs(self, project_id, limit=100):
        session = self.get_session()
        try:
            return session.query(Log)\
                .filter(Log.project_id == project_id)\
                .order_by(Log.timestamp.desc())\
                .limit(limit).all()
        finally:
            session.close()
    
    def create_vulnerability(self, project_id, title, description, target, cvss_score, severity, **kwargs):
        session = self.get_session()
        try:
            vuln = Vulnerability(
                project_id=project_id,
                title=title,
                description=description,
                target=target,
                cvss_score=cvss_score,
                severity=severity,
                **kwargs
            )
            session.add(vuln)
            session.commit()
            return vuln
        finally:
            session.close()
    
    def get_vulnerabilities(self, project_id, min_cvss=0.0):
        session = self.get_session()
        try:
            return session.query(Vulnerability)\
                .filter(Vulnerability.project_id == project_id)\
                .filter(Vulnerability.cvss_score >= min_cvss)\
                .order_by(Vulnerability.cvss_score.desc()).all()
        finally:
            session.close()
    
    def get_project_stats(self, project_id):
        session = self.get_session()
        try:
            stats = {
                'total_logs': session.query(Log).filter(Log.project_id == project_id).count(),
                'total_vulnerabilities': session.query(Vulnerability).filter(Vulnerability.project_id == project_id).count(),
                'critical': session.query(Vulnerability).filter(
                    Vulnerability.project_id == project_id,
                    Vulnerability.severity == 'Critical'
                ).count(),
                'high': session.query(Vulnerability).filter(
                    Vulnerability.project_id == project_id,
                    Vulnerability.severity == 'High'
                ).count(),
                'medium': session.query(Vulnerability).filter(
                    Vulnerability.project_id == project_id,
                    Vulnerability.severity == 'Medium'
                ).count(),
                'low': session.query(Vulnerability).filter(
                    Vulnerability.project_id == project_id,
                    Vulnerability.severity == 'Low'
                ).count()
            }
            return stats
        finally:
            session.close()


db_manager = DatabaseManager()
'@

Set-Content -Path "core\database.py" -Value $databaseContent -Encoding UTF8
Write-Host "✓ core/database.py creado" -ForegroundColor Green

# ============== core/__init__.py ==============
Write-Host "[2/8] Creando core/__init__.py..." -ForegroundColor Yellow

$coreInitContent = @'
from core.database import db_manager, DatabaseManager, Project

__all__ = ['db_manager', 'DatabaseManager', 'Project']
'@

Set-Content -Path "core\__init__.py" -Value $coreInitContent -Encoding UTF8
Write-Host "✓ core/__init__.py creado" -ForegroundColor Green

# ============== setup.py ==============
Write-Host "[3/8] Creando setup.py..." -ForegroundColor Yellow

$setupContent = @'
#!/usr/bin/env python3
"""Berebrum - Setup Script"""

import sys
from pathlib import Path

print("=" * 60)
print("  🧠 Berebrum - Inicialización")
print("=" * 60)
print("")

if sys.version_info < (3, 10):
    print("❌ Se requiere Python 3.10 o superior")
    sys.exit(1)

print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

# Crear directorios
Path("database").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
Path("logs").mkdir(exist_ok=True)
print("✓ Directorios creados")

# Inicializar base de datos
try:
    from core.database import db_manager
    db_manager.init_db()
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)

print("")
print("=" * 60)
print("✅ Setup completado exitosamente!")
print("=" * 60)
print("")
print("Próximos pasos:")
print("  python cli/main.py")
print("")
'@

Set-Content -Path "setup.py" -Value $setupContent -Encoding UTF8
Write-Host "✓ setup.py creado" -ForegroundColor Green

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✓ Archivos CORE creados!                                 ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Ahora ejecuta para instalar:" -ForegroundColor Cyan
Write-Host "  .\scripts\install-windows.ps1" -ForegroundColor White
Write-Host ""