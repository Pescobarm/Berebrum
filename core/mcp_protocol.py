from abc import ABC, abstractmethod
from datetime import datetime
import json
import traceback

from core.safety import ScopeGuardian
from database.session import SessionLocal
from database.models import AttackFlow, Finding, Project


class MCPTool(ABC):
    def __init__(
        self,
        name,
        description,
        mitre_id,
        project_id,
        guardian: ScopeGuardian,
        parent_action_id=None,
    ):
        self.name = name
        self.description = description
        self.mitre_id = mitre_id
        self.project_id = project_id
        self.guardian = guardian
        self.parent_action_id = parent_action_id  # Para construir el árbol de ataque

    def run(self, target, **kwargs):
        """
        Método MAESTRO que envuelve la ejecución.
        1. Valida Scope.
        2. Registra inicio en AttackFlow.
        3. Ejecuta la herramienta.
        4. Guarda resultados y cierra log.
        """
        # 1. Validación de Seguridad
        if not self.guardian.validate_target(target):
            self._log_action(
                target, kwargs, "BLOCKED", "Target fuera del Scope permitido."
            )
            return {"status": "BLOCKED", "error": "Target out of scope"}

        # 2. Ejecución Real (Envuelto en Try/Catch para no romper el programa)
        try:
            print(f"[*] 🚀 Ejecutando {self.name} contra {target}...")
            start_time = datetime.now()

            # --- Aquí corre la herramienta específica ---
            result = self._execute(target, **kwargs)
            # --------------------------------------------

            # 3. Guardar Éxito
            self._log_action(
                target=target,
                command=str(kwargs),
                status="SUCCESS",
                output=json.dumps(result, default=str)[:1000],  # Guardamos resumen
            )
            return result

        except Exception as e:
            # 4. Manejo de Errores
            error_msg = f"Error runtime: {str(e)}"
            print(f"[!] 💥 Fallo en {self.name}: {error_msg}")
            traceback.print_exc()

            self._log_action(
                target=target, command=str(kwargs), status="ERROR", output=error_msg
            )
            return {"status": "ERROR", "error": error_msg}

    @abstractmethod
    def _execute(self, target, **kwargs):
        """
        Lógica específica de la herramienta (Nmap, Hydra, etc).
        Debe ser implementada por cada subclase.
        """
        pass

    def _log_action(self, target, command, status, output):
        """Registra la acción en la tabla AttackFlow de la DB"""
        session = SessionLocal()
        try:
            log = AttackFlow(
                project_id=self.project_id,
                tool_used=self.name,
                command_executed=f"Target: {target} | Args: {command}",
                status=status,
                output_summary=output,
                parent_action_id=self.parent_action_id,
            )
            session.add(log)
            session.commit()
            # Retornamos el ID para que la siguiente herramienta pueda ser "hija" de esta
            return log.id
        except Exception as e:
            print(f"[!] Error guardando log en DB: {e}")
        finally:
            session.close()

    def save_finding(self, title, target, evidence, severity, cvss_score):
        """Helper para guardar vulnerabilidades directamente en la DB"""
        session = SessionLocal()
        try:
            finding = Finding(
                project_id=self.project_id,
                tool_name=self.name,
                vulnerability_name=title,
                target_host=target,
                mitre_id=self.mitre_id,
                severity=severity,
                cvss_score=cvss_score,
                evidence=str(evidence),
            )
            session.add(finding)
            session.commit()
            print(f"[+] 🚩 HALLAZGO REGISTRADO: {title} ({severity})")
        except Exception as e:
            print(f"[!] Error guardando finding: {e}")
        finally:
            session.close()
