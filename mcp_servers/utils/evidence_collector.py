import os
from datetime import datetime
from config.settings import OUTPUT_DIR
from core.mcp_protocol import MCPTool


class EvidenceCollector(MCPTool):
    def __init__(self, project_id, guardian, parent_id=None):
        super().__init__(
            name="Evidence Collector",
            description="Guarda notas, logs crudos o screenshots simulados",
            mitre_id="T1592",  # Host Discovery / Collection
            project_id=project_id,
            guardian=guardian,
            parent_action_id=parent_id,
        )

    def _execute(self, target, note_content=None, file_name="evidence.txt"):
        # 1. Preparar directorio del proyecto
        project_dir = OUTPUT_DIR / f"project_{self.project_id}"
        os.makedirs(project_dir, exist_ok=True)

        # 2. Definir ruta final
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_name = f"{timestamp}_{file_name}"
        file_path = project_dir / final_name

        # 3. Escribir evidencia
        content = f"--- EVIDENCE LOG ---\nTarget: {target}\nTime: {timestamp}\n\n{note_content}\n"

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        return {
            "status": "SAVED",
            "file_path": str(file_path),
            "size_bytes": len(content),
        }
