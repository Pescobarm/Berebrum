"""
Berebrum - Database Models
Modelos SQLAlchemy con integración MITRE ATT&CK y CVSS
"""

from typing import List
from sqlalchemy import case
from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    ForeignKey,
    Boolean,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    scope_ips = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default="active")

    logs = relationship("Log", back_populates="project", cascade="all, delete-orphan")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="project", cascade="all, delete-orphan"
    )


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
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
    error_message = Column(Text)

    project = relationship("Project", back_populates="logs")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    target = Column(String(255))
    port = Column(Integer)
    service = Column(String(100))
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    severity = Column(String(20))
    mitre_technique_id = Column(String(20))
    mitre_technique_name = Column(String(200))
    mitre_tactic = Column(String(100))
    cve_id = Column(String(50))
    cwe_id = Column(String(50))
    proof_of_concept = Column(Text)
    remediation = Column(Text)
    false_positive = Column(Boolean, default=False)

    project = relationship("Project", back_populates="vulnerabilities")


class DatabaseManager:
    def __init__(self, database_url="sqlite:///database/berebrum.db"):
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def init_db(self):
        """Inicializa la base de datos"""
        Base.metadata.create_all(self.engine)
        print("✓ Base de datos inicializada")

    def get_session(self):
        """Retorna una nueva sesión"""
        return self.SessionLocal()

    # ==================== PROJECT OPERATIONS ====================

    def create_project(self, name, scope_ips, description=None):
        """Crea un nuevo proyecto"""
        session = self.get_session()
        try:
            project = Project(name=name, scope_ips=scope_ips, description=description)
            session.add(project)
            session.commit()
            session.refresh(project)
            return project
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_project(self, project_id):
        """Obtiene un proyecto por ID"""
        session = self.get_session()
        try:
            return session.query(Project).filter(Project.id == project_id).first()
        finally:
            session.close()

    def get_project_by_name(self, name):
        """Obtiene un proyecto por nombre"""
        session = self.get_session()
        try:
            return session.query(Project).filter(Project.name == name).first()
        finally:
            session.close()

    def list_projects(self, status=None):
        """Lista proyectos"""
        session = self.get_session()
        try:
            query = session.query(Project)
            if status:
                query = query.filter(Project.status == status)
            return query.order_by(Project.created_at.desc()).all()
        finally:
            session.close()

    def update_project_status(self, project_id, status):
        """Actualiza el estado de un proyecto"""
        session = self.get_session()
        try:
            project = session.query(Project).filter(Project.id == project_id).first()
            if project:
                project.status = status
                session.commit()
            return project
        finally:
            session.close()

    # ==================== LOG OPERATIONS ====================

    def create_log(self, project_id, tool_name, target, command, **kwargs):
        """Crea un nuevo log"""
        session = self.get_session()
        try:
            log = Log(
                project_id=project_id,
                tool_name=tool_name,
                target=target,
                command=command,
                **kwargs,
            )
            session.add(log)
            session.commit()
            session.refresh(log)
            return log
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_logs(self, project_id, limit=100):
        """Obtiene logs de un proyecto"""
        session = self.get_session()
        try:
            return (
                session.query(Log)
                .filter(Log.project_id == project_id)
                .order_by(Log.timestamp.desc())
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_logs_by_tool(self, project_id, tool_name):
        """Obtiene logs de una herramienta específica"""
        session = self.get_session()
        try:
            return (
                session.query(Log)
                .filter(Log.project_id == project_id)
                .filter(Log.tool_name == tool_name)
                .order_by(Log.timestamp.desc())
                .all()
            )
        finally:
            session.close()

    # ==================== VULNERABILITY OPERATIONS ====================

    def create_vulnerability(
        self, project_id, title, description, target, cvss_score, severity, **kwargs
    ):
        """Crea una nueva vulnerabilidad"""
        session = self.get_session()
        try:
            vuln = Vulnerability(
                project_id=project_id,
                title=title,
                description=description,
                target=target,
                cvss_score=cvss_score,
                severity=severity,
                **kwargs,
            )
            session.add(vuln)
            session.commit()
            session.refresh(vuln)
            return vuln
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_vulnerabilities(self, project_id, min_cvss=0.0):
        """Obtiene vulnerabilidades de un proyecto"""
        session = self.get_session()
        try:
            return (
                session.query(Vulnerability)
                .filter(Vulnerability.project_id == project_id)
                .filter(Vulnerability.cvss_score >= min_cvss)
                .filter(Vulnerability.false_positive == False)
                .order_by(Vulnerability.cvss_score.desc())
                .all()
            )
        finally:
            session.close()

    def get_vulnerability(self, vuln_id):
        """Obtiene una vulnerabilidad por ID"""
        session = self.get_session()
        try:
            return (
                session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            )
        finally:
            session.close()

    def update_vulnerability(self, vuln_id, **kwargs):
        """Actualiza una vulnerabilidad"""
        session = self.get_session()
        try:
            vuln = (
                session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            )
            if vuln:
                for key, value in kwargs.items():
                    if hasattr(vuln, key):
                        setattr(vuln, key, value)
                session.commit()
            return vuln
        finally:
            session.close()

    # ==================== STATISTICS ====================

    def get_project_stats(self, project_id):
        """Obtiene estadísticas de un proyecto"""
        session = self.get_session()
        try:
            # Total de logs
            total_logs = session.query(Log).filter(Log.project_id == project_id).count()

            # Total de vulnerabilidades
            total_vulns = (
                session.query(Vulnerability)
                .filter(Vulnerability.project_id == project_id)
                .filter(Vulnerability.false_positive == False)
                .count()
            )

            # Por severidad
            critical = (
                session.query(Vulnerability)
                .filter(Vulnerability.project_id == project_id)
                .filter(Vulnerability.severity == "Critical")
                .filter(Vulnerability.false_positive == False)
                .count()
            )

            high = (
                session.query(Vulnerability)
                .filter(Vulnerability.project_id == project_id)
                .filter(Vulnerability.severity == "High")
                .filter(Vulnerability.false_positive == False)
                .count()
            )

            medium = (
                session.query(Vulnerability)
                .filter(Vulnerability.project_id == project_id)
                .filter(Vulnerability.severity == "Medium")
                .filter(Vulnerability.false_positive == False)
                .count()
            )

            low = (
                session.query(Vulnerability)
                .filter(Vulnerability.project_id == project_id)
                .filter(Vulnerability.severity == "Low")
                .filter(Vulnerability.false_positive == False)
                .count()
            )

            # Herramientas ejecutadas
            tools_used = (
                session.query(Log.tool_name)
                .filter(Log.project_id == project_id)
                .distinct()
                .count()
            )

            # Logs exitosos
            successful_logs = (
                session.query(Log)
                .filter(Log.project_id == project_id)
                .filter(Log.success == True)
                .count()
            )

            return {
                "total_logs": total_logs,
                "total_vulnerabilities": total_vulns,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "tools_used": tools_used,
                "successful_logs": successful_logs,
                "failed_logs": total_logs - successful_logs,
            }
        finally:
            session.close()

    def get_mitre_coverage(self, project_id):
        """Obtiene cobertura de técnicas MITRE"""
        session = self.get_session()
        try:
            techniques = (
                session.query(Log.mitre_technique_id, Log.mitre_technique_name)
                .filter(Log.project_id == project_id)
                .filter(Log.mitre_technique_id.isnot(None))
                .distinct()
                .all()
            )

            return [{"id": t[0], "name": t[1]} for t in techniques]
        finally:
            session.close()

    def get_all_severities(self) -> List[str]:
        """
        Obtiene todas las severidades únicas de las vulnerabilidades.

        Returns:
            Lista de strings con las severidades únicas
        """
        try:
            with self.get_session() as session:
                # Query para obtener severidades únicas
                severities = (
                    session.query(Vulnerability.severity)
                    .distinct()
                    .order_by(
                        # Ordenar por severidad (Critical -> High -> Medium -> Low)
                        case(
                            (Vulnerability.severity == "Critical", 1),
                            (Vulnerability.severity == "High", 2),
                            (Vulnerability.severity == "Medium", 3),
                            (Vulnerability.severity == "Low", 4),
                            else_=5,
                        )
                    )
                    .all()
                )

                # Convertir de tuplas a lista de strings
                result = [s[0] for s in severities if s[0]]

                # Si no hay vulnerabilidades, retornar lista por defecto
                if not result:
                    return ["Critical", "High", "Medium", "Low"]

                return result

        except Exception as e:
            print(f"Error al obtener severidades: {e}")
            # Retornar lista por defecto en caso de error
            return ["Critical", "High", "Medium", "Low"]

    def get_all_tool_names(self) -> List[str]:
        """
        Obtiene todos los nombres de herramientas únicos de los logs.

        Returns:
            Lista de strings con los nombres de herramientas únicos (ordenados)
        """
        try:
            with self.get_session() as session:
                # Query para obtener nombres únicos de herramientas
                tools = (
                    session.query(Log.tool_name)
                    .distinct()
                    .order_by(Log.tool_name)
                    .all()
                )

                # Convertir de tuplas a lista de strings, filtrando None
                result = [t[0] for t in tools if t[0]]

                return result

        except Exception as e:
            print(f"Error al obtener nombres de herramientas: {e}")
            return []


# Instancia global
db_manager = DatabaseManager()
