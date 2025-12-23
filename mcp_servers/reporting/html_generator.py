import os
from datetime import datetime
from config.settings import OUTPUT_DIR
from database.session import SessionLocal
from database.models import Finding, Project


class HtmlReporter:
    def __init__(self, project_id):
        self.project_id = project_id
        self.session = SessionLocal()

    def generate(self):
        # 1. Obtener datos
        project = self.session.query(Project).filter_by(id=self.project_id).first()
        findings = (
            self.session.query(Finding).filter_by(project_id=self.project_id).all()
        )

        if not project:
            return {"status": "ERROR", "msg": "Proyecto no encontrado"}

        # 2. Crear estructura HTML (CSS simple incluido)
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <title>Reporte de Seguridad - {project.name}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }}
                header {{ background-color: #2c3e50; color: #fff; padding: 20px; border-radius: 8px 8px 0 0; }}
                h1 {{ margin: 0; }}
                .meta {{ font-size: 0.9em; color: #bdc3c7; margin-top: 5px; }}
                .summary {{ background-color: #fff; padding: 20px; border-radius: 0 0 8px 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; background-color: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }}
                th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: #fff; }}
                tr:hover {{ background-color: #f1f1f1; }}
                .badge {{ padding: 5px 10px; border-radius: 4px; color: #fff; font-size: 0.8em; font-weight: bold; }}
                .High {{ background-color: #e74c3c; }}
                .Medium {{ background-color: #f39c12; }}
                .Low {{ background-color: #3498db; }}
                footer {{ text-align: center; margin-top: 40px; color: #7f8c8d; font-size: 0.8em; }}
            </style>
        </head>
        <body>
            <header>
                <h1>🛡️ Berebrum Security Report</h1>
                <div class="meta">Proyecto: {project.name} | Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
            </header>

            <div class="summary">
                <h2>Resumen Ejecutivo</h2>
                <p><strong>Objetivo (Scope):</strong> {project.scope_cidrs}</p>
                <p><strong>Total Hallazgos:</strong> {len(findings)}</p>
            </div>

            <h2>Detalle de Hallazgos</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Severidad</th>
                        <th>Vulnerabilidad</th>
                        <th>Target</th>
                        <th>Evidencia / Notas</th>
                    </tr>
                </thead>
                <tbody>
        """

        # 3. Llenar la tabla dinámicamente
        for f in findings:
            evidence_snippet = (
                (f.evidence[:50] + "...") if len(f.evidence) > 50 else f.evidence
            )
            html_content += f"""
                    <tr>
                        <td>{f.id}</td>
                        <td><span class="badge {f.severity}">{f.severity}</span></td>
                        <td>{f.vulnerability_name}</td>
                        <td>{f.target_host}</td>
                        <td>{evidence_snippet}</td>
                    </tr>
            """

        # 4. Cerrar HTML
        html_content += """
                </tbody>
            </table>
            <footer>Generado por Berebrum 2.0 - NeuroStrike Core</footer>
        </body>
        </html>
        """

        # 5. Guardar archivo
        project_dir = OUTPUT_DIR / f"project_{self.project_id}"
        os.makedirs(project_dir, exist_ok=True)
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        file_path = project_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        self.session.close()
        return {"status": "SUCCESS", "path": str(file_path)}
