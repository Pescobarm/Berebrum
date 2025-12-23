from database.session import SessionLocal
from database.models import AttackFlow, Project
from datetime import datetime
import os


# --- 1. FUNCIÓN QUE FALTABA (GUARDAR LOGS) ---
def save_attack_flow(
    session, project_id, tool_name, target, output_summary, command_executed=""
):
    """
    Guarda una entrada en la bitácora de ataque (AttackFlow).
    Es llamada por main.py cada vez que ejecutas una herramienta.
    """
    try:
        # Determinamos estado simple basado en el texto de salida
        status = "SUCCESS"
        if (
            "Error" in output_summary
            or "Exception" in output_summary
            or "Connection refused" in output_summary
        ):
            status = "FAILED"

        entry = AttackFlow(
            project_id=project_id,
            tool_used=tool_name,
            target=target,
            status=status,
            result_summary=output_summary[:200] + "...",  # Breve resumen para DB
            output_summary=output_summary,  # Log completo
            command_executed=command_executed,
            timestamp=datetime.utcnow(),
        )
        session.add(entry)
        session.commit()
        print(f"    [+] Log guardado en AttackFlow: {tool_name} -> {target}")
    except Exception as e:
        print(f"    ⚠️ Error guardando log: {e}")
        session.rollback()


# --- 2. FUNCIÓN DE VISUALIZACIÓN (VER LOGS) ---
def view_attack_flow(project_id):
    """
    Muestra la cronología de herramientas ejecutadas (AttackFlow) en la terminal.
    """
    session = SessionLocal()
    try:
        project = session.query(Project).filter_by(id=project_id).first()
        if not project:
            print("    ❌ Proyecto no encontrado.")
            return

        # Consultamos la tabla de AttackFlow (no Findings)
        logs = (
            session.query(AttackFlow)
            .filter_by(project_id=project_id)
            .order_by(AttackFlow.timestamp)
            .all()
        )

        print("\n" + "=" * 90)
        print(f" ⚔️  BITÁCORA DE OPERACIONES (ATTACK FLOW): {project.name}")
        print("=" * 90)

        if not logs:
            print("\n    🤷 No hay herramientas ejecutadas aún.")
            return

        # Cabecera
        print(f"\n{'HORA':<10} | {'HERRAMIENTA':<20} | {'OBJETIVO':<25} | {'ESTADO'}")
        print("-" * 90)

        for log in logs:
            ts = log.timestamp.strftime("%H:%M:%S")
            status_icon = "✅" if log.status == "SUCCESS" else "❌"

            print(
                f"{ts:<10} | {log.tool_used[:20]:<20} | {log.target[:25]:<25} | {status_icon} {log.status}"
            )

        print("-" * 90)
        input("\n    🛑 Presiona Enter para volver...")

    finally:
        session.close()
