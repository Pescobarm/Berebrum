from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
    JSON,
)
from sqlalchemy.orm import relationship
from datetime import datetime
from .session import Base


class Project(Base):
    """Define un alcance de trabajo (Pentest)"""

    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    scope_cidrs = Column(Text, nullable=False)  # Guardaremos IPs separadas por coma
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="ACTIVE")  # ACTIVE, ARCHIVED

    # Relaciones
    findings = relationship(
        "Finding", back_populates="project", cascade="all, delete-orphan"
    )
    attack_flow = relationship(
        "AttackFlow", back_populates="project", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Vulnerabilidades o Hallazgos detectados"""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))

    # Datos Técnicos
    tool_name = Column(String)  # Ej: Nmap, LFI_Fuzzer
    vulnerability_name = Column(String)  # Ej: Open Port 22, Local File Inclusion
    target_host = Column(String)  # IP o Dominio afectado

    # Estándares (MITRE & CVSS)
    mitre_id = Column(String)  # Ej: T1190
    cvss_score = Column(Float)  # 0.0 - 10.0
    cvss_vector = Column(String)  # CVSS:3.1/AV:N...
    severity = Column(String)  # Critical, High, Medium, Low
    target = Column(String)
    # Evidencia
    evidence = Column(Text)  # Output crudo o path a screenshot
    reproduction_steps = Column(Text)  # Pasos para replicar

    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="findings")


class AttackFlow(Base):
    """
    La Historia del Ataque.
    Registra cada paso ejecutado, quién lo ejecutó y qué resultó.
    """

    __tablename__ = "attack_flow"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))

    timestamp = Column(DateTime, default=datetime.utcnow)
    tool_used = Column(String)
    command_executed = Column(Text)  # El comando exacto o payload

    # Contexto de Ejecución
    status = Column(String)  # SUCCESS, FAILED, BLOCKED (por Safety Rail)
    output_summary = Column(Text)  # Resumen corto del resultado
    artifacts_path = Column(String)  # Ruta a logs completos en /outputs
    target = Column(String)

    # Árbol de Ataque (Relación Padre-Hijo)
    # Ej: El ataque de Hydra (Hijo) vino del hallazgo de Nmap (Padre)
    parent_action_id = Column(Integer, ForeignKey("attack_flow.id"), nullable=True)

    project = relationship("Project", back_populates="attack_flow")
    children = relationship("AttackFlow", backref="parent", remote_side=[id])
