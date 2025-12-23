import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# --- CONFIGURACIÓN DE RUTAS ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from database.session import engine
from database.models import Project, Finding, AttackFlow

# from core.safety import ScopeGuardian # Descomentar si se usa validación aquí

# Intentamos importar Graphviz
try:
    import graphviz

    HAS_GRAPHVIZ = True
except ImportError:
    HAS_GRAPHVIZ = False

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(
    page_title="BEREBRUM C2",
    page_icon="💀",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- ESTILOS CSS ---
st.markdown(
    """
    <style>
        .stApp { background-color: #0e1117; }
        .kpi-card { border-radius: 8px; padding: 15px; text-align: center; margin-bottom: 10px; color: white; border: 1px solid #333; }
        .bg-crit { background: linear-gradient(135deg, #a71d2a 0%, #dc3545 100%); }
        .bg-high { background: linear-gradient(135deg, #c65f0a 0%, #fd7e14 100%); }
        .bg-med { background: linear-gradient(135deg, #d39e00 0%, #ffc107 100%); color: black !important; }
        .bg-low { background: linear-gradient(135deg, #1e7e34 0%, #28a745 100%); }
        .bg-info { background: #2b3035; }
        .kpi-num { font-size: 28px; font-weight: bold; }
        .kpi-lbl { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
        
        /* CAJAS VERDES PARA PASOS */
        .step-box { 
            background-color: #1c2029; 
            padding: 15px; 
            border-left: 4px solid #00ff41; 
            margin-bottom: 10px; 
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #e0e0e0;
        }
    </style>
""",
    unsafe_allow_html=True,
)

Session = sessionmaker(bind=engine)


# --- FUNCIONES DE BASE DE DATOS ---
def get_data(project_id):
    session = Session()
    try:
        findings = session.query(Finding).filter_by(project_id=project_id).all()
        flow = (
            session.query(AttackFlow)
            .filter_by(project_id=project_id)
            .order_by(AttackFlow.timestamp.desc())
            .all()
        )
        return findings, flow
    finally:
        session.close()


def get_projects():
    session = Session()
    try:
        return session.query(Project).all()
    finally:
        session.close()


# --- FUNCIONES AUXILIARES ---
def generate_reproduction_steps(vuln_name, target):
    """Genera pasos lógicos basados en el tipo de vuln"""
    vuln_lower = vuln_name.lower()
    steps = []

    if "sql" in vuln_lower:
        steps = [
            f"1. Navegar a la URL objetivo: {target}",
            "2. Identificar parámetros de entrada (GET/POST).",
            "3. Insertar payload de prueba: ' OR 1=1--",
            "4. Observar si la respuesta cambia o muestra errores de DB.",
            "5. Usar SQLMap o Burp para extracción de datos.",
        ]
    elif "xss" in vuln_lower:
        steps = [
            f"1. Ubicar el campo de entrada en {target}",
            "2. Inyectar payload de prueba: <script>alert(1)</script>",
            "3. Si es Stored, recargar la página donde se muestra el comentario.",
            "4. Si es Reflected, enviar el enlace a la víctima (simulado).",
            "5. Confirmar ejecución de JavaScript (Alert box).",
        ]
    elif "rce" in vuln_lower or "command" in vuln_lower:
        steps = [
            f"1. Identificar endpoint vulnerable en {target}",
            "2. Probar concatenación de comandos: ; id o | whoami",
            "3. Analizar la respuesta HTTP buscando salida del sistema (uid=0).",
            "4. Escalar a Reverse Shell si es posible.",
        ]
    elif "ssl" in vuln_lower:
        steps = [
            f"1. Usar 'testssl.sh' contra {target}",
            "2. Verificar protocolos soportados (SSLv3, TLS1.0).",
            "3. Comprobar fuerza de cifrados (Sweet32, Logjam).",
            "4. Validar fecha de expiración del certificado.",
        ]
    else:
        steps = [
            f"1. Analizar el recurso: {target}",
            "2. Revisar cabeceras y configuraciones por defecto.",
            "3. Comparar respuesta con documentación oficial.",
            "4. Validar impacto en confidencialidad o integridad.",
        ]
    return steps


def generate_curl(target, evidence_sample=""):
    method = "GET"
    payload_flag = ""
    target = target or "http://localhost"

    if evidence_sample and "POST" in evidence_sample[:10]:
        method = "POST"
        try:
            parts = evidence_sample.split("\n\n")
            if len(parts) > 1:
                body = parts[1].strip()
                payload_flag = f"-d '{body}'"
        except:
            pass

    return (
        f"curl -X {method} '{target}' {payload_flag} -H 'User-Agent: Berebrum/2.0' -v"
    )


def trigger_replay(tool, target):
    """Función simulada para relanzar herramientas"""
    st.toast(f"🚀 RELANZANDO: {tool} contra {target}...", icon="🔄")
    # Aquí se conectaría con la cola de tareas o subprocess


# --- SIDEBAR ---
st.sidebar.title("💀 BEREBRUM OPS")
projects = get_projects()
if not projects:
    st.error("⚠️ No hay proyectos. Crea uno con 'python main.py'")
    st.stop()

project_map = {f"{p.name} (ID: {p.id})": p.id for p in projects}
sel_proj_label = st.sidebar.selectbox("🎯 Misión Actual", list(project_map.keys()))
pid = project_map[sel_proj_label]
selected_project = [p for p in projects if p.id == pid][0]

findings, attack_flow = get_data(pid)

# DataFrames
df_find = pd.DataFrame(
    [
        {
            "ID": f.id,
            "Sev": f.severity,
            "Name": f.vulnerability_name,
            "Target": getattr(f, "target", "N/A"),
            "Mitre": f.mitre_id,
            "Evidence": f.evidence,
        }
        for f in findings
    ]
)

df_flow = pd.DataFrame(
    [
        {
            "Time": f.timestamp,
            "Tool": f.tool_used,
            "Target": getattr(f, "target", "N/A"),
            "Status": f.status,
            "Cmd": f.command_executed,
            "Out": f.output_summary,
        }
        for f in attack_flow
    ]
)

unique_targets = list(
    set(
        [t for t in df_flow["Target"].unique() if t != "N/A"]
        + selected_project.scope_cidrs.split(",")
    )
)

# --- HEADER ---
c1, c2 = st.columns([3, 1])
c1.title(f"🚩 {selected_project.name}")
c2.markdown(f"**Scope:** `{selected_project.scope_cidrs}`")

# --- TABS ---
tab_dash, tab_map, tab_vulns, tab_ops = st.tabs(
    ["📊 COMMAND CENTER", "🗺️ TOPOLOGÍA", "🧬 LABORATORIO (BURP)", "⚔️ OPERACIONES"]
)

# ================= TAB 1: COMMAND CENTER =================
with tab_dash:
    k1, k2, k3, k4, k5 = st.columns(5)

    crit = len(df_find[df_find["Sev"] == "Critical"])
    high = len(df_find[df_find["Sev"] == "High"])
    med = len(df_find[df_find["Sev"] == "Medium"])
    low = len(df_find[df_find["Sev"] == "Low"])

    k1.markdown(
        f'<div class="kpi-card bg-crit"><div class="kpi-lbl">CRITICAL</div><div class="kpi-num">{crit}</div></div>',
        unsafe_allow_html=True,
    )
    k2.markdown(
        f'<div class="kpi-card bg-high"><div class="kpi-lbl">HIGH</div><div class="kpi-num">{high}</div></div>',
        unsafe_allow_html=True,
    )
    k3.markdown(
        f'<div class="kpi-card bg-med"><div class="kpi-lbl">MEDIUM</div><div class="kpi-num">{med}</div></div>',
        unsafe_allow_html=True,
    )
    k4.markdown(
        f'<div class="kpi-card bg-low"><div class="kpi-lbl">LOW</div><div class="kpi-num">{low}</div></div>',
        unsafe_allow_html=True,
    )
    k5.markdown(
        f'<div class="kpi-card bg-info"><div class="kpi-lbl">EVENTS</div><div class="kpi-num">{len(df_flow)}</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown("---")
    g1, g2 = st.columns([1, 2])
    with g1:
        st.subheader("Riesgo Global")
        if not df_find.empty:
            colors = {
                "Critical": "#dc3545",
                "High": "#fd7e14",
                "Medium": "#ffc107",
                "Low": "#28a745",
                "Info": "#17a2b8",
            }
            fig = px.pie(
                df_find, names="Sev", hole=0.6, color="Sev", color_discrete_map=colors
            )
            fig.update_layout(
                showlegend=False,
                margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig, use_container_width=True)
    with g2:
        st.subheader("Actividad Reciente")
        if not df_flow.empty:
            df_grp = (
                df_flow.set_index("Time").resample("H").size().reset_index(name="Count")
            )
            fig2 = px.bar(
                df_grp, x="Time", y="Count", color_discrete_sequence=["#00ff41"]
            )
            fig2.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="white",
            )
            st.plotly_chart(fig2, use_container_width=True)

# ================= TAB 2: TOPOLOGÍA =================
with tab_map:
    st.subheader("🌐 Mapa de Red")
    if HAS_GRAPHVIZ:
        if not df_flow.empty:
            graph = graphviz.Digraph()
            graph.attr(rankdir="LR", bgcolor="#0e1117")
            graph.attr(
                "node",
                shape="box",
                style="filled",
                fontcolor="white",
                fontname="Courier",
            )
            graph.node("C2", label="💀 BEREBRUM", fillcolor="#222", color="#00ff41")
            seen = set()
            for t in df_flow["Target"].unique():
                if t and t != "N/A" and t not in seen:
                    seen.add(t)
                    has_crit = not df_find[
                        (df_find["Target"] == t) & (df_find["Sev"] == "Critical")
                    ].empty
                    fill = "#8a1c26" if has_crit else "#333"
                    graph.node(t, label=t, fillcolor=fill, color="white")
                    graph.edge("C2", t, color="#555")
            st.graphviz_chart(graph)
        else:
            st.warning("Sin datos de red.")
    else:
        st.warning("⚠️ Librería 'Graphviz' no detectada.")

# ================= TAB 3: LABORATORIO (BURP READY) =================
with tab_vulns:
    st.subheader("🧬 Análisis y Replicación")
    if df_find.empty:
        st.info("No hay vulnerabilidades.")
    else:
        for idx, row in df_find.iterrows():
            sev_icon = "🔴" if row["Sev"] == "Critical" else "🟠"
            with st.expander(
                f"{sev_icon} [{row['Sev']}] {row['Name']} @ {row['Target']}"
            ):

                c_conf, c_curl = st.columns(2)
                with c_conf:
                    st.markdown("#### 🛠️ Config")
                    st.text_input(
                        "Target URL", row["Target"], key=f"t_{idx}", disabled=True
                    )
                    st.caption("MITRE ATT&CK: " + (row["Mitre"] or "N/A"))
                with c_curl:
                    st.markdown("#### 🚀 Payload (cURL)")
                    st.code(
                        generate_curl(row["Target"], row["Evidence"]), language="bash"
                    )

                st.markdown("---")

                c_steps, c_evidence = st.columns([1, 1])
                with c_steps:
                    st.markdown("#### 👣 Paso a Paso (Replicación)")
                    pasos = generate_reproduction_steps(row["Name"], row["Target"])
                    for p in pasos:
                        st.markdown(
                            f'<div class="step-box">{p}</div>', unsafe_allow_html=True
                        )
                with c_evidence:
                    st.markdown("#### 📸 Evidencia Técnica (Raw)")
                    st.code(row["Evidence"], language="http")

# ================= TAB 4: OPERACIONES =================
with tab_ops:
    # Encabezado con Botón de descarga
    col_title, col_dl = st.columns([3, 1])
    with col_title:
        st.subheader("⚔️ Bitácora de Operaciones & Replay")
    with col_dl:
        if not df_flow.empty:
            # Convertir a CSV para descarga
            csv = df_flow.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇️ Descargar Log (CSV)",
                data=csv,
                file_name=f"berebrum_log_{pid}_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                key="dl_log_btn",
            )

    st.markdown("---")

    if df_flow.empty:
        st.info("No hay registros de operaciones en este proyecto.")
    else:
        # Iteramos sobre el historial (Full Width)
        for i, row in df_flow.iterrows():
            status_icon = "✅" if row["Status"] == "SUCCESS" else "❌"

            # Usamos un expander que ocupa todo el ancho
            with st.expander(
                f"{status_icon} {row['Time'].strftime('%Y-%m-%d %H:%M:%S')} | 🛠️ {row['Tool']} ➜ 🎯 {row['Target']}"
            ):

                # Dividimos el contenido del expander: Izquierda (Detalles), Derecha (Acciones)
                c_det, c_act = st.columns([4, 1])

                with c_det:
                    st.markdown(f"**Comando Ejecutado:** `{row['Cmd']}`")
                    st.markdown("**Salida:**")
                    st.code(row["Out"], language="text")

                with c_act:
                    st.markdown("#### Acciones")
                    if st.button(
                        "🔄 Re-Lanzar",
                        key=f"replay_{i}",
                        help="Ejecutar nuevamente esta herramienta con los mismos parámetros",
                    ):
                        trigger_replay(row["Tool"], row["Target"])
