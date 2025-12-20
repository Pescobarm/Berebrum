"""
Berebrum - Dashboard Web
Versión Ejecutiva - Sin JSON, Solo Visualizaciones Profesionales
"""

import sys
from pathlib import Path

DASHBOARD_DIR = Path(__file__).parent
ROOT_DIR = DASHBOARD_DIR.parent

sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(DASHBOARD_DIR))

import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import json
import ast

# =====================================================
# CONFIGURACIÓN DE PÁGINA
# =====================================================
st.set_page_config(page_title="Berebrum Dashboard", page_icon="🧠", layout="wide")


# =====================================================
# CSS
# =====================================================
def load_css_fallback():
    st.markdown(
        """
    <style>
    .severity-badge {
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
        font-size: 14px;
        display: inline-block;
        margin: 2px;
    }
    .critical { background-color: #dc3545; color: white; }
    .high { background-color: #fd7e14; color: white; }
    .medium { background-color: #ffc107; color: black; }
    .low { background-color: #28a745; color: white; }
    .none { background-color: #6c757d; color: white; }
    
    .metric-card {
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        color: white;
        font-weight: bold;
    }
    .metric-critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
    .metric-high { background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); }
    .metric-medium { background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); color: black; }
    .metric-low { background: linear-gradient(135deg, #28a745 0%, #218838 100%); }
    .metric-neutral { background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%); }
    
    .metric-value {
        font-size: 36px;
        font-weight: bold;
        margin: 10px 0;
    }
    .metric-label {
        font-size: 14px;
        opacity: 0.9;
    }
    
    .owasp-badge {
        background: linear-gradient(135deg, #6f42c1 0%, #5a32a3 100%);
        color: white;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 14px;
        display: inline-block;
        margin: 5px;
    }
    
    .recon-badge {
        background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
        color: white;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 14px;
        display: inline-block;
        margin: 5px;
    }
    
    .brute-force-badge {
        background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        color: white;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 14px;
        display: inline-block;
        margin: 5px;
    }
    
    .vuln-card {
        border-left: 5px solid;
        padding: 15px;
        margin: 10px 0;
        background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%);
        border-radius: 5px;
        color: #e0e0e0;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }
    .vuln-card h4 {
        color: #ffffff;
        margin-top: 0;
    }
    .vuln-card code {
        background-color: rgba(255, 255, 255, 0.1);
        color: #00d4ff;
        padding: 2px 6px;
        border-radius: 3px;
    }
    .vuln-card strong {
        color: #ffffff;
    }
    .vuln-critical { border-left-color: #dc3545; }
    .vuln-high { border-left-color: #fd7e14; }
    .vuln-medium { border-left-color: #ffc107; }
    .vuln-low { border-left-color: #28a745; }
    
    .attack-step-card {
        padding: 15px;
        margin: 10px 0;
        border-radius: 8px;
        border-left: 4px solid;
    }
    .attack-step-vulnerable {
        background: rgba(220, 53, 69, 0.1);
        border-left-color: #dc3545;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )


try:
    from utils.style_loader import load_custom_styles

    load_custom_styles()
except ImportError:
    load_css_fallback()

# =====================================================
# DATABASE
# =====================================================
db_manager = None

try:
    from core.database import db_manager

    db_manager.init_db()
except ImportError as e:
    st.error(f"❌ Error al importar módulos de base de datos")
    st.code(str(e), language=None)
    st.stop()
except Exception as e:
    st.error(f"❌ Error al inicializar la base de datos: {str(e)}")
    st.stop()

if db_manager is None:
    st.error("❌ Database manager no se pudo inicializar")
    st.stop()

# =====================================================
# FUNCIONES HELPER
# =====================================================


def format_duration(duration_seconds):
    if duration_seconds is None:
        return "N/A"
    return f"{duration_seconds:.2f}s"


def format_timestamp(timestamp, format_str="%d/%m/%y"):
    if timestamp is None:
        return "N/A"
    return timestamp.strftime(format_str)


def safe_json_parse(output_str):
    if not output_str:
        return None
    try:
        return json.loads(output_str)
    except:
        try:
            return ast.literal_eval(output_str)
        except:
            return None


# Categorías y herramientas
TOOL_CATEGORIES = {
    "OWASP Top 10": {
        "icon": "🛡️",
        "badge": "owasp-badge",
        "tools": [
            "SQL Injection Scanner",
            "XSS Detector",
            "SSTI Detector",
            "CSRF Tester",
            "LFI/RFI Scanner",
            "Command Injection Tester",
        ],
    },
    "Reconocimiento": {
        "icon": "🔍",
        "badge": "recon-badge",
        "tools": [
            "Port Scanner",
            "Banner Grabber",
            "Subdomain Enumerator",
            "Web Directory Scanner",
            "HTTP Header Analyzer",
            "DNS Information Gatherer",
            "SSL/TLS Analyzer",
        ],
    },
    "Brute Force": {
        "icon": "🔓",
        "badge": "brute-force-badge",
        "tools": ["SSH Brute Force", "FTP Brute Force"],
    },
}

TOOL_ICONS = {
    "SQL Injection Scanner": "💉",
    "XSS Detector": "🔗",
    "SSTI Detector": "💉",
    "CSRF Tester": "🔐",
    "LFI/RFI Scanner": "🗂️",
    "Port Scanner": "🔍",
    "Banner Grabber": "🏷️",
    "Subdomain Enumerator": "🌐",
    "Web Directory Scanner": "📁",
    "HTTP Header Analyzer": "📋",
    "DNS Information Gatherer": "🔎",
    "SSL/TLS Analyzer": "🔒",
    "SSH Brute Force": "🔓",
    "FTP Brute Force": "📂",
}

# =====================================================
# PARSERS POR HERRAMIENTA
# =====================================================


def render_sql_injection_results(parsed, log):
    """Parser para SQL Injection Scanner"""
    st.markdown("### 💉 Análisis de Inyección SQL")

    col1, col2, col3 = st.columns(3)

    with col1:
        vuln = parsed.get("vulnerable", False)
        vuln_text = "🚨 VULNERABLE" if vuln else "✅ SEGURO"
        color = "metric-critical" if vuln else "metric-low"
        st.markdown(
            f"""
            <div class="metric-card {color}">
                <div class="metric-value" style="font-size: 20px;">{vuln_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        db_type = parsed.get("database_type", "Unknown")
        st.markdown(
            f"""
            <div class="metric-card metric-neutral">
                <div class="metric-label">🗄️ BASE DE DATOS</div>
                <div class="metric-value" style="font-size: 18px;">{db_type}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        conf = parsed.get("confidence", 0)
        st.markdown(
            f"""
            <div class="metric-card metric-low">
                <div class="metric-label">📊 CONFIANZA</div>
                <div class="metric-value">{conf}%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Vulnerabilidades encontradas
    vulns = parsed.get("vulnerabilities", [])
    if vulns:
        st.markdown("---")
        st.markdown(f"### 🚨 {len(vulns)} Vulnerabilidades Detectadas")

        for vuln in vulns:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.error(
                    f"**{vuln.get('severity', 'High')}** - Parámetro: `{vuln.get('parameter')}`"
                )
                st.caption(f"Técnica: **{vuln.get('technique', 'N/A').upper()}**")
            with col2:
                st.metric("Payload", f"{len(vuln.get('payload', ''))} chars")

            if vuln.get("evidence"):
                st.info(f"📝 {vuln.get('evidence')}")

    # Attack Flow Summary
    attack_summary = parsed.get("attack_summary", {})
    attack_flow = parsed.get("attack_flow", [])

    if attack_summary or attack_flow:
        st.markdown("---")
        st.markdown("### 🔥 Attack Flow - Secuencia del Ataque")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Pasos Totales", attack_summary.get("total_steps", len(attack_flow))
            )
        with col2:
            vuln_steps = attack_summary.get("vulnerable_steps", 0)
            total_steps = attack_summary.get("total_steps", len(attack_flow))
            st.metric(
                "Pasos Vulnerables",
                vuln_steps,
                delta=f"{total_steps - vuln_steps} seguros",
                delta_color="inverse",
            )
        with col3:
            phases = attack_summary.get("phases", [])
            st.metric("Fases Ejecutadas", len(phases))
        with col4:
            techs = attack_summary.get("techniques_detected", [])
            st.metric("Técnicas Detectadas", len(techs))

        # Mostrar steps vulnerables destacados
        if attack_flow:
            vulnerable_steps = [
                s
                for s in attack_flow
                if s.get("detection", {}).get("vulnerable", False)
            ]
            clean_steps = [
                s
                for s in attack_flow
                if not s.get("detection", {}).get("vulnerable", False)
            ]

            if vulnerable_steps:
                st.markdown("#### 🚨 Pasos Críticos Detectados - Listos para Replicar:")

                for step in vulnerable_steps:
                    step_num = step.get("step", 0)
                    phase = step.get("phase", "Unknown")
                    payload = step.get("payload", "")
                    technique = step.get("detection", {}).get("technique", "Unknown")
                    evidence = step.get("detection", {}).get("evidence", "")
                    confidence = step.get("detection", {}).get("confidence", 0)

                    # Header del step
                    st.markdown(
                        f"""
                        <div class="attack-step-card attack-step-vulnerable">
                            <strong>🚨 Paso {step_num}: {phase} - {technique.upper()}</strong>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    # =====================================================
                    # REQUEST COMPLETO - FORMATO BURP SUITE
                    # =====================================================
                    st.markdown("##### 📤 REQUEST HTTP (Copiar a Burp Suite)")

                    request_info = step.get("request", {})
                    method = request_info.get("method", "GET")
                    url = step.get("url", "")
                    headers = request_info.get("headers", {})
                    params = request_info.get("params", {})
                    body = request_info.get("body", "")

                    # Construir request en formato HTTP raw
                    from urllib.parse import urlparse, unquote

                    parsed_url = urlparse(url)
                    host = parsed_url.netloc or "target.com"
                    path = parsed_url.path or "/"
                    query_string = parsed_url.query or ""

                    # DECODIFICAR URL encoding para hacerlo legible
                    query_string_decoded = unquote(query_string) if query_string else ""
                    path_decoded = unquote(path)

                    # Identificar dónde está el payload
                    payload_location = "Unknown"
                    if params and any(payload in str(v) for v in params.values()):
                        payload_location = "Query Parameter"
                    elif body and payload in str(body):
                        payload_location = "Request Body"
                    elif headers and any(payload in str(v) for v in headers.values()):
                        payload_location = "HTTP Header"

                    # Construir HTTP request raw (DECODED)
                    http_request = f"{method} {path_decoded}"
                    if query_string_decoded:
                        http_request += f"?{query_string_decoded}"
                    http_request += " HTTP/1.1\n"
                    http_request += f"Host: {host}\n"

                    # Headers
                    if headers:
                        for h_name, h_value in headers.items():
                            # Decodificar valores de headers también
                            h_value_decoded = (
                                unquote(str(h_value)) if h_value else h_value
                            )
                            http_request += f"{h_name}: {h_value_decoded}\n"

                    # Body si existe (también decodificado)
                    if body:
                        body_decoded = unquote(str(body)) if body else body
                        http_request += f"\n{body_decoded}"

                    col1, col2 = st.columns([3, 1])

                    with col1:
                        st.code(http_request, language="http")

                    with col2:
                        st.metric("Método", method)
                        st.metric("Payload en", payload_location)
                        st.metric("Payload Size", f"{len(payload)} bytes")

                    # =====================================================
                    # PAYLOAD DETALLADO
                    # =====================================================
                    st.markdown("##### 💉 PAYLOAD INYECTADO")

                    # Decodificar payload para mostrar
                    from urllib.parse import unquote

                    payload_decoded = unquote(payload) if payload else payload

                    # Mostrar exactamente dónde y cómo se inyectó
                    if params:
                        st.markdown("**Parámetros afectados:**")
                        for param_name, param_value in params.items():
                            # Decodificar valores de parámetros
                            param_value_decoded = (
                                unquote(str(param_value))
                                if param_value
                                else param_value
                            )
                            if (
                                payload in str(param_value)
                                or payload_decoded in param_value_decoded
                            ):
                                st.code(
                                    f"{param_name}={param_value_decoded}", language=None
                                )
                                st.caption(
                                    f"⚠️ Payload inyectado en parámetro: `{param_name}`"
                                )

                    if body:
                        st.markdown("**Body del request:**")
                        body_decoded = unquote(str(body)) if body else body
                        st.code(
                            body_decoded,
                            language="json" if body.startswith("{") else None,
                        )

                    # Payload puro
                    st.markdown("**Payload puro (copiar directamente):**")
                    st.code(payload_decoded, language=None)

                    # =====================================================
                    # RESPONSE DETALLADO
                    # =====================================================
                    st.markdown("##### 📥 RESPONSE HTTP")

                    response = step.get("response", {})
                    status_code = response.get("status_code", 0)
                    response_time = response.get("time", 0)
                    response_size = response.get("size", 0)
                    response_headers = response.get("headers", {})
                    response_body = response.get("body", "")

                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        status_color = "🟢" if 200 <= status_code < 300 else "🔴"
                        st.metric("Status", f"{status_color} {status_code}")
                    with col2:
                        st.metric("Tiempo", f"{response_time*1000:.0f}ms")
                    with col3:
                        st.metric("Tamaño", f"{response_size/1024:.1f}KB")
                    with col4:
                        st.metric("Headers", len(response_headers))

                    # Response headers
                    if response_headers:
                        show_headers = st.checkbox(
                            "📋 Mostrar Response Headers",
                            key=f"headers_ssti_step_{step_num}_{log.id}",  # ✅ SOLUCIÓN: Con log ID
                        )
                        if show_headers:
                            st.markdown("**Response Headers:**")
                            for h_name, h_value in response_headers.items():
                                st.code(f"{h_name}: {h_value}", language=None)

                    # Response body preview
                    if response_body:
                        st.markdown("**Response Body (preview):**")
                        # Mostrar primeros 500 chars del body
                        body_preview = response_body[:500]
                        if len(response_body) > 500:
                            body_preview += (
                                "\n\n... (truncado, total: {len(response_body)} chars)"
                            )

                        st.code(
                            body_preview,
                            language=(
                                "html" if "<html" in response_body.lower() else None
                            ),
                        )

                    # =====================================================
                    # EVIDENCIA Y ANÁLISIS
                    # =====================================================
                    if evidence:
                        st.markdown("##### 🔍 EVIDENCIA DE VULNERABILIDAD")
                        st.error(f"**{evidence}**")

                        # Explicar por qué es vulnerable
                        st.markdown("**¿Por qué es vulnerable?**")
                        if "error" in evidence.lower() or "syntax" in evidence.lower():
                            st.info(
                                "📘 La aplicación reveló un error de SQL, indicando que el input no está sanitizado correctamente. Esto permite inyectar código SQL arbitrario."
                            )
                        elif (
                            "true" in evidence.lower() or "success" in evidence.lower()
                        ):
                            st.info(
                                "📘 La condición inyectada retornó verdadero, permitiendo bypass de autenticación o extracción de datos."
                            )

                    st.metric(
                        "🎯 Confianza",
                        f"{confidence}%",
                        delta="Alta" if confidence > 80 else "Media",
                    )

                    # =====================================================
                    # GUÍA DE REPLICACIÓN
                    # =====================================================
                    st.markdown("##### 🔧 CÓMO REPLICAR EN BURP SUITE")

                    # Decodificar para la guía
                    from urllib.parse import unquote

                    payload_decoded = unquote(payload) if payload else payload
                    param_name_display = list(params.keys())[0] if params else "N/A"

                    st.markdown(
                        f"""
                    **Paso a paso:**
                    
                    1. **Interceptar request** original a `{host}{path}`
                    2. **Identificar parámetro vulnerable:** `{param_name_display}`
                    3. **Reemplazar valor** con el payload:
                       ```
                       {payload_decoded}
                       ```
                    4. **Enviar request** y verificar response
                    5. **Buscar en response:** {evidence[:50] if evidence else 'Cambios en comportamiento'}...
                    
                    **En Burp Suite Repeater:**
                    - Copia el request HTTP completo de arriba
                    - Pégalo en la pestaña Request
                    - Modifica el parámetro vulnerable con el payload
                    - Click en "Send"
                    - Verifica la response
                    
                    **Nota:** Burp Suite automáticamente hace el URL encoding cuando envías el request,
                    así que copia el payload tal como aparece arriba (sin %27, %3D, etc.)
                    """
                    )

                    # Separador entre steps
                    st.markdown("---")
                    st.markdown("")  # Espacio adicional

            # Tabla resumen de TODOS los steps
            st.markdown("#### 📋 Tabla Completa de la Secuencia:")

            steps_data = []
            for step in attack_flow[:25]:  # Mostrar hasta 25 steps
                is_vuln = step.get("detection", {}).get("vulnerable", False)
                response = step.get("response", {})
                steps_data.append(
                    {
                        "Step": step.get("step", 0),
                        "Fase": step.get("phase", "N/A"),
                        "Payload": step.get("payload", "")[:35] + "...",
                        "Resultado": "🚨 VULNERABLE" if is_vuln else "✅ Seguro",
                        "Técnica": (
                            step.get("detection", {}).get("technique", "-").upper()
                            if is_vuln
                            else "-"
                        ),
                        "HTTP": response.get("status_code", 0),
                        "Tiempo (ms)": f"{response.get('time', 0)*1000:.0f}",
                    }
                )

            if steps_data:
                df = pd.DataFrame(steps_data)
                st.dataframe(df, use_container_width=True, hide_index=True)

                if len(attack_flow) > 25:
                    st.caption(f"Mostrando 25 de {len(attack_flow)} pasos totales")

        # Resumen técnico para técnicos
        if attack_summary.get("techniques_detected"):
            st.markdown("#### 🔧 Técnicas de Ataque Detectadas:")
            techniques = attack_summary.get("techniques_detected", [])
            params = attack_summary.get("parameters_tested", [])

            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Técnicas:** {', '.join([t.upper() for t in techniques])}")
            with col2:
                st.info(f"**Parámetros probados:** {', '.join(params)}")


def render_ssti_results(parsed, log):
    """Parser para SSTI Detector con Attack Flow completo"""
    st.markdown("### 💉 Server-Side Template Injection (SSTI) Detection")

    # Métricas principales
    vulnerable = parsed.get("vulnerable", False)
    vuln_count = parsed.get("vulnerability_count", 0)
    severity = parsed.get("severity", "None")
    confidence = parsed.get("confidence", 0)

    col1, col2, col3 = st.columns(3)

    with col1:
        status_color = (
            "metric-critical"
            if severity == "Critical"
            else "metric-high" if vulnerable else "metric-low"
        )
        status_text = "🚨 VULNERABLE" if vulnerable else "✅ SEGURO"
        st.markdown(
            f"""
            <div class="metric-card {status_color}">
                <div class="metric-label">ESTADO</div>
                <div class="metric-value">{status_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        severity_class_map = {
            "Critical": "metric-critical",
            "High": "metric-high",
            "Medium": "metric-medium",
            "Low": "metric-low",
            "None": "metric-neutral",
        }
        severity_class = severity_class_map.get(severity, "metric-neutral")
        st.markdown(
            f"""
            <div class="metric-card {severity_class}">
                <div class="metric-label">💥 SEVERIDAD</div>
                <div class="metric-value">{severity}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card metric-low">
                <div class="metric-label">📊 CONFIANZA</div>
                <div class="metric-value">{confidence}%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Vulnerabilidades encontradas
    vulns = parsed.get("vulnerabilities", [])
    if vulns:
        st.markdown("---")
        st.markdown(f"### 🚨 {len(vulns)} Vulnerabilidades SSTI Detectadas")

        for vuln in vulns:
            col1, col2 = st.columns([3, 1])
            with col1:
                engine = vuln.get("subtype", "Unknown Engine")
                phase = vuln.get("phase", "detection")
                phase_badge = "🔴 RCE" if phase == "exploitation" else "🟡 Detection"
                st.error(
                    f"**{vuln.get('severity', 'High')} - {engine}** {phase_badge} - Parámetro: `{vuln.get('parameter')}`"
                )
                st.caption(
                    f"Engine: **{vuln.get('engine', 'N/A').upper()}** | Fase: **{phase.upper()}**"
                )
            with col2:
                st.metric("CVSS", vuln.get("cvss_score", 0))

            if vuln.get("evidence"):
                if phase == "exploitation":
                    st.error(f"⚠️ **RCE CONFIRMADO:** {vuln.get('evidence')}")
                else:
                    st.warning(f"📝 {vuln.get('evidence')}")

    # Attack Flow Summary
    attack_summary = parsed.get("attack_summary", {})
    attack_flow = parsed.get("attack_flow", [])

    if attack_summary or attack_flow:
        st.markdown("---")
        st.markdown("### 🔥 Attack Flow - Secuencia del Ataque")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Pasos Totales", attack_summary.get("total_steps", len(attack_flow))
            )
        with col2:
            vuln_steps = attack_summary.get("vulnerable_steps", 0)
            total_steps = attack_summary.get("total_steps", len(attack_flow))
            st.metric(
                "Pasos Vulnerables",
                vuln_steps,
                delta=f"{total_steps - vuln_steps} seguros",
                delta_color="inverse",
            )
        with col3:
            phases = attack_summary.get("phases", [])
            st.metric("Fases Ejecutadas", len(phases))
        with col4:
            engines = attack_summary.get("engines_detected", [])
            st.metric("Engines Detectados", len(engines))

        # Mostrar steps vulnerables destacados
        if attack_flow:
            vulnerable_steps = [
                s
                for s in attack_flow
                if s.get("detection", {}).get("vulnerable", False)
            ]

            if vulnerable_steps:
                st.markdown("#### 🚨 Pasos Críticos Detectados - Listos para Replicar:")

                for step in vulnerable_steps:
                    step_num = step.get("step", 0)
                    phase = step.get("phase", "Unknown")
                    payload = step.get("payload", "")
                    technique = step.get("detection", {}).get("technique", "Unknown")
                    evidence = step.get("detection", {}).get("evidence", "")
                    confidence_step = step.get("detection", {}).get("confidence", 0)

                    is_rce = (
                        "exploitation" in technique.lower()
                        or "exploitation" in phase.lower()
                    )

                    st.markdown(
                        f"""
                        <div class="attack-step-card attack-step-vulnerable">
                            <strong>{'🔴' if is_rce else '🚨'} Paso {step_num}: {phase} - {technique.upper()}</strong>
                            {' ⚠️ RCE CONFIRMED' if is_rce else ''}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    # REQUEST HTTP
                    st.markdown("##### 📤 REQUEST HTTP (Copiar a Burp Suite)")

                    request_info = step.get("request", {})
                    method = request_info.get("method", "GET")
                    url = step.get("url", "")
                    headers = request_info.get("headers", {})
                    params = request_info.get("params", {})
                    body = request_info.get("body", "")

                    from urllib.parse import urlparse, unquote

                    parsed_url = urlparse(url)
                    host = parsed_url.netloc or "target.com"
                    path = parsed_url.path or "/"
                    query_string = parsed_url.query or ""

                    query_string_decoded = unquote(query_string) if query_string else ""
                    path_decoded = unquote(path)

                    payload_location = "Unknown"
                    if params and any(payload in str(v) for v in params.values()):
                        payload_location = "Query Parameter"
                    elif body and payload in str(body):
                        payload_location = "Request Body"

                    http_request = f"{method} {path_decoded}"
                    if query_string_decoded:
                        http_request += f"?{query_string_decoded}"
                    http_request += " HTTP/1.1\n"
                    http_request += f"Host: {host}\n"

                    if headers:
                        for h_name, h_value in headers.items():
                            h_value_decoded = (
                                unquote(str(h_value)) if h_value else h_value
                            )
                            http_request += f"{h_name}: {h_value_decoded}\n"

                    if body:
                        body_decoded = unquote(str(body)) if body else body
                        http_request += f"\n{body_decoded}"

                    col1, col2 = st.columns([3, 1])

                    with col1:
                        st.code(http_request, language="http")

                    with col2:
                        st.metric("Método", method)
                        st.metric("Payload en", payload_location)
                        st.metric("Size", f"{len(payload)} bytes")
                        if is_rce:
                            st.error("⚠️ RCE")

                    # PAYLOAD
                    st.markdown("##### 💉 PAYLOAD INYECTADO")

                    payload_decoded = unquote(payload) if payload else payload

                    if params:
                        st.markdown("**Parámetros afectados:**")
                        for param_name, param_value in params.items():
                            param_value_decoded = (
                                unquote(str(param_value))
                                if param_value
                                else param_value
                            )
                            if (
                                payload in str(param_value)
                                or payload_decoded in param_value_decoded
                            ):
                                st.code(
                                    f"{param_name}={param_value_decoded}", language=None
                                )
                                st.caption(
                                    f"⚠️ Payload inyectado en parámetro: `{param_name}`"
                                )

                    st.markdown("**Payload puro (copiar directamente):**")
                    st.code(
                        payload_decoded,
                        language="python" if "{{" in payload_decoded else None,
                    )

                    # RESPONSE
                    st.markdown("##### 📥 RESPONSE HTTP")

                    response = step.get("response", {})
                    status_code = response.get("status_code", 0)
                    response_time = response.get("time", 0)
                    response_size = response.get("size", 0)
                    response_headers = response.get("headers", {})
                    response_body = response.get("body", "")

                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        status_color = "🟢" if 200 <= status_code < 300 else "🔴"
                        st.metric("Status", f"{status_color} {status_code}")
                    with col2:
                        st.metric("Tiempo", f"{response_time*1000:.0f}ms")
                    with col3:
                        st.metric("Tamaño", f"{response_size/1024:.1f}KB")
                    with col4:
                        st.metric("Headers", len(response_headers))

                    if response_headers:
                        show_headers = st.checkbox(
                            "📋 Mostrar Response Headers",
                            key=f"headers_ssti_step_{step_num}_{log.id}",
                        )
                        if show_headers:
                            st.markdown("**Response Headers:**")
                            for h_name, h_value in response_headers.items():
                                st.code(f"{h_name}: {h_value}", language=None)

                    if response_body:
                        st.markdown("**Response Body (preview):**")
                        body_preview = response_body[:1000]
                        if len(response_body) > 1000:
                            body_preview += f"\n\n... (truncado)"

                        if "uid=" in body_preview or "gid=" in body_preview:
                            st.error("⚠️ **RCE DETECTADO EN RESPONSE**")

                        st.code(
                            body_preview,
                            language=(
                                "html" if "<html" in response_body.lower() else None
                            ),
                        )

                    # EVIDENCIA
                    if evidence:
                        st.markdown("##### 🔍 EVIDENCIA DE VULNERABILIDAD")

                        if is_rce:
                            st.error(f"🔴 **RCE CONFIRMADO:** {evidence}")
                            st.error(
                                """
                            **CRITICAL - Remote Code Execution**
                            
                            • Ejecutar comandos del SO
                            • Leer archivos del servidor
                            • Acceso a secrets
                            • Crear reverse shell
                            • Compromiso COMPLETO
                            """
                            )
                        else:
                            st.error(f"**{evidence}**")
                            st.info("📘 Template ejecutado sin sanitización")

                    st.metric("🎯 Confianza", f"{confidence_step}%")

                    # GUÍA BURP SUITE
                    st.markdown("##### 🔧 CÓMO REPLICAR EN BURP SUITE")

                    param_name_display = list(params.keys())[0] if params else "N/A"

                    st.markdown(
                        f"""
                    **Paso a paso:**
                    1. Interceptar request a `{host}{path}`
                    2. Modificar parámetro `{param_name_display}`
                    3. Payload: `{payload_decoded[:80]}...`
                    4. Send y verificar response
                    5. Buscar: {evidence[:50] if evidence else 'Código ejecutado'}
                    
                    {"⚠️ **ADVERTENCIA:** RCE completo detectado" if is_rce else ""}
                    """
                    )

                    st.markdown("---")

            # Tabla resumen
            st.markdown("#### 📋 Tabla Completa:")

            steps_data = []
            for step in attack_flow[:25]:
                is_vuln = step.get("detection", {}).get("vulnerable", False)
                response = step.get("response", {})
                technique = step.get("detection", {}).get("technique", "-")
                is_rce = "exploitation" in technique.lower() if is_vuln else False

                steps_data.append(
                    {
                        "Step": step.get("step", 0),
                        "Fase": step.get("phase", "N/A"),
                        "Payload": step.get("payload", "")[:30] + "...",
                        "Resultado": (
                            ("🔴 RCE" if is_rce else "🚨 VULN") if is_vuln else "✅ OK"
                        ),
                        "Técnica": technique.upper() if is_vuln else "-",
                        "HTTP": response.get("status_code", 0),
                    }
                )

            if steps_data:
                df = pd.DataFrame(steps_data)
                st.dataframe(df, use_container_width=True, hide_index=True)

        # Resumen
        if attack_summary.get("engines_detected"):
            st.markdown("#### 🔧 Engines Detectados:")
            engines = attack_summary.get("engines_detected", [])
            params = attack_summary.get("parameters_tested", [])

            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Engines:** {', '.join([e.upper() for e in engines])}")
            with col2:
                st.info(f"**Parámetros:** {', '.join(params)}")


def render_port_scanner_results(parsed, log):
    """Parser para Port Scanner"""
    st.markdown("### 🔍 Escaneo de Puertos")

    open_ports = parsed.get("open_ports", []) or []
    closed_ports = parsed.get("closed_ports", 0) or 0

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(
            "Puertos Abiertos",
            len(open_ports),
            delta="Requiere atención" if open_ports else "OK",
            delta_color="inverse" if open_ports else "normal",
        )
    with col2:
        st.metric(
            "Puertos Cerrados", closed_ports, delta="Seguros", delta_color="normal"
        )
    with col3:
        total = len(open_ports) + closed_ports
        st.metric("Total Escaneados", total)

    if open_ports:
        st.markdown("---")
        st.markdown("#### 🚪 Puertos Abiertos Detectados:")

        ports_data = []
        for port_info in open_ports:
            # Obtener banner de forma segura
            banner = port_info.get("banner") or "N/A"
            if banner and len(banner) > 40:
                banner = banner[:40] + "..."

            ports_data.append(
                {
                    "🔢 Puerto": port_info.get("port") or "N/A",
                    "📡 Estado": port_info.get("state") or "open",
                    "🔧 Servicio": port_info.get("service") or "Unknown",
                    "🏷️ Banner": banner,
                }
            )

        df = pd.DataFrame(ports_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("✅ No se detectaron puertos abiertos")


def render_subdomain_results(parsed, log):
    """Parser para Subdomain Enumerator"""
    st.markdown("### 🌐 Enumeración de Subdominios")

    subdomains = parsed.get("subdomains", []) or []

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Subdominios Encontrados", len(subdomains))
    with col2:
        active = len([s for s in subdomains if s.get("status") == "active"])
        st.metric("Subdominios Activos", active)

    if subdomains:
        st.markdown("---")

        subdomain_data = []
        for sub in subdomains[:20]:  # Mostrar primeros 20
            subdomain_data.append(
                {
                    "🌐 Subdominio": sub.get("domain") or "N/A",
                    "📡 Estado": (
                        "✅ Activo" if sub.get("status") == "active" else "❌ Inactivo"
                    ),
                    "🔢 IP": sub.get("ip") or "N/A",
                }
            )

        df = pd.DataFrame(subdomain_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

        if len(subdomains) > 20:
            st.caption(f"Mostrando 20 de {len(subdomains)} subdominios")


def render_directory_scanner_results(parsed, log):
    """Parser para Web Directory Scanner"""
    st.markdown("### 📁 Escaneo de Directorios Web")

    found_dirs = parsed.get("found_directories", []) or []

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Directorios Encontrados", len(found_dirs))
    with col2:
        sensitive = len([d for d in found_dirs if d.get("sensitive", False)])
        st.metric(
            "Directorios Sensibles",
            sensitive,
            delta="Revisar" if sensitive else "OK",
            delta_color="inverse" if sensitive else "normal",
        )

    if found_dirs:
        st.markdown("---")

        dir_data = []
        for dir_info in found_dirs[:30]:
            status_icon = "🚨" if dir_info.get("sensitive") else "✅"
            dir_data.append(
                {
                    "Estado": status_icon,
                    "📂 Directorio": dir_info.get("path") or "N/A",
                    "📡 HTTP": dir_info.get("status_code") or "N/A",
                    "📦 Tamaño": f"{(dir_info.get('size') or 0) / 1024:.1f}KB",
                }
            )

        df = pd.DataFrame(dir_data)
        st.dataframe(df, use_container_width=True, hide_index=True)


def render_banner_grabber_results(parsed, log):
    """Parser para Banner Grabber"""
    st.markdown("### 🏷️ Captura de Banners")

    banners = parsed.get("banners", []) or []

    st.metric("Servicios Identificados", len(banners))

    if banners:
        st.markdown("---")

        for banner in banners:
            col1, col2 = st.columns([1, 3])
            with col1:
                st.metric("Puerto", banner.get("port") or "N/A")
            with col2:
                st.code(banner.get("banner") or "No banner available", language=None)


def render_http_header_results(parsed, log):
    """Parser para HTTP Header Analyzer"""
    st.markdown("### 📋 Análisis de Headers HTTP")

    headers = parsed.get("headers", {})
    security_headers = parsed.get("security_headers", {})

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Headers Totales", len(headers))
    with col2:
        missing = len([h for h, v in security_headers.items() if not v])
        st.metric(
            "Headers de Seguridad Faltantes",
            missing,
            delta="Vulnerabilidad",
            delta_color="inverse",
        )

    st.markdown("---")
    st.markdown("#### 🔒 Headers de Seguridad:")

    security_data = []
    for header, present in security_headers.items():
        security_data.append(
            {
                "🔐 Header": header,
                "📡 Estado": "✅ Presente" if present else "❌ Ausente",
                "⚠️ Riesgo": "Bajo" if present else "Alto",
            }
        )

    df = pd.DataFrame(security_data)
    st.dataframe(df, use_container_width=True, hide_index=True)


def render_dns_results(parsed, log):
    """Parser para DNS Information Gatherer"""
    st.markdown("### 🔎 Información DNS")

    records = parsed.get("records", {})

    st.metric("Tipos de Registros", len(records))

    st.markdown("---")

    for record_type, values in records.items():
        if values:
            st.markdown(f"#### 📝 Registros {record_type}:")
            for value in values:
                st.code(value, language=None)


def render_ssl_tls_results(parsed, log):
    """Parser para SSL/TLS Analyzer"""
    st.markdown("### 🔒 Análisis SSL/TLS")

    valid = parsed.get("valid_certificate", False)
    expires = parsed.get("expires_in_days") or 0

    col1, col2, col3 = st.columns(3)
    with col1:
        status = "✅ Válido" if valid else "❌ Inválido"
        st.markdown(
            f"""
            <div class="metric-card {'metric-low' if valid else 'metric-critical'}">
                <div class="metric-label">CERTIFICADO</div>
                <div class="metric-value" style="font-size: 20px;">{status}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        delta_text = "Renovar pronto" if expires < 30 else "OK"
        st.metric("Expira en", f"{expires} días", delta=delta_text)
    with col3:
        version = parsed.get("tls_version") or "N/A"
        st.metric("Versión TLS", version)


def render_brute_force_results(parsed, log, tool_name):
    """Parser para SSH/FTP Brute Force"""
    st.markdown(f"### 🔓 {tool_name}")

    credentials_found = parsed.get("credentials_found", []) or []
    total_attempts = parsed.get("total_attempts", 0) or 0

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Intentos Totales", total_attempts)
    with col2:
        st.metric(
            "Credenciales Válidas",
            len(credentials_found),
            delta="Vulnerabilidad Crítica" if credentials_found else "Seguro",
            delta_color="inverse" if credentials_found else "normal",
        )

    if credentials_found:
        st.markdown("---")
        st.error("🚨 CREDENCIALES VÁLIDAS ENCONTRADAS:")

        cred_data = []
        for cred in credentials_found:
            cred_data.append(
                {
                    "👤 Usuario": cred.get("username") or "N/A",
                    "🔑 Contraseña": cred.get("password") or "N/A",
                    "⏰ Encontrado": cred.get("timestamp") or "N/A",
                }
            )

        df = pd.DataFrame(cred_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("✅ No se encontraron credenciales válidas")


def render_lfi_rfi_results(parsed, log):
    """Parser para LFI/RFI Scanner con Attack Flow"""
    st.markdown("### 🗂️ LFI/RFI Scanner - File Inclusion Detection")

    # Métricas principales
    vulnerable = parsed.get("vulnerable", False)
    vuln_count = parsed.get("vulnerability_count", 0)
    severity = parsed.get("severity", "None")
    confidence = parsed.get("confidence", 0)
    auto_scan = parsed.get("auto_scan", False)

    col1, col2, col3 = st.columns(3)

    with col1:
        status_color = "metric-critical" if vulnerable else "metric-low"
        status_text = "🚨 VULNERABLE" if vulnerable else "✅ SEGURO"
        st.markdown(
            f"""
            <div class="metric-card {status_color}">
                <div class="metric-label">ESTADO</div>
                <div class="metric-value">{status_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        severity_class_map = {
            "Critical": "metric-critical",
            "High": "metric-high",
            "Medium": "metric-medium",
            "Low": "metric-low",
            "None": "metric-neutral",
        }
        severity_class = severity_class_map.get(severity, "metric-neutral")
        st.markdown(
            f"""
            <div class="metric-card {severity_class}">
                <div class="metric-label">💥 SEVERIDAD</div>
                <div class="metric-value">{severity}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card metric-low">
                <div class="metric-label">📊 CONFIANZA</div>
                <div class="metric-value">{confidence}%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Scan Details
    scan_details = parsed.get("scan_details", {})
    if scan_details:
        st.markdown("---")
        st.markdown("### 📋 Scan Details")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Intentos", scan_details.get("total_attempts", 0))
        with col2:
            st.metric("Bloqueados", scan_details.get("blocked_attempts", 0))
        with col3:
            st.metric("Errores", scan_details.get("error_attempts", 0))
        
        # Tabla de parámetros
        params_tested = scan_details.get("parameters_tested", [])
        if params_tested:
            st.markdown("#### Parámetros Probados")
            
            params_list = []
            for p in params_tested[:10]:
                if isinstance(p, dict):
                    params_list.append({
                        "Parámetro": f"?{p.get('parameter', 'N/A')}=",
                        "Resultado": p.get("result", "N/A").upper(),
                        "Payloads": p.get("payloads_tested", 0)
                    })
                else:
                    params_list.append({
                        "Parámetro": f"?{p}=",
                        "Resultado": "TESTED",
                        "Payloads": 4
                    })
            
            if params_list:
                import pandas as pd
                st.dataframe(pd.DataFrame(params_list), use_container_width=True, hide_index=True)
            
            if len(params_tested) > 10:
                st.info(f"... y {len(params_tested) - 10} parámetros más probados")

    # Protection Analysis
    protection = parsed.get("protection_analysis", {})
    if protection and not vulnerable:
        st.markdown("---")
        st.markdown("### 🛡️  Protection Analysis")
        
        rating = protection.get("security_rating", "Unknown")
        if rating == "Good":
            st.success(f"✅ Security Rating: {rating}")
        elif rating == "Fair":
            st.warning(f"⚠️  Security Rating: {rating}")
        else:
            st.error(f"❌ Security Rating: {rating}")
        
        # Protecciones detectadas
        protections = protection.get("protections_detected", [])
        if protections:
            st.markdown("#### 🔒 Protecciones Detectadas")
            for i, prot in enumerate(protections, 1):
                st.markdown(f"**{i}. {prot['type']} - {prot['confidence']} confidence**")
                st.write(f"📝 {prot['description']}")
                if prot.get("evidence"):
                    st.write(f"🔍 Evidencia: {prot['evidence']}")
                st.markdown("")  # Espacio
        
        # Estadísticas
        stats = protection.get("statistics", {})
        if stats:
            st.markdown("#### 📊 Estadísticas del Scan")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total", stats.get("total_attempts", 0))
            with col2:
                st.metric("Bloqueados", stats.get("blocked", 0))
            with col3:
                st.metric("Errores", stats.get("errors", 0))

    # Vulnerabilidades encontradas
    vulns = parsed.get("vulnerabilities", [])
    if vulns:
        st.markdown("---")
        st.markdown(f"### 🚨 {len(vulns)} Vulnerabilidades Detectadas")

        for vuln in vulns:
            col1, col2 = st.columns([3, 1])
            with col1:
                vuln_type = vuln.get("type", "LFI")
                st.error(f"**{vuln.get('severity', 'High')} - {vuln_type}** - Parámetro: `{vuln.get('parameter')}`")
                st.caption(f"CWE: **{vuln.get('cwe_id', 'N/A')}** | MITRE: **{vuln.get('mitre_technique_id', 'N/A')}**")
            with col2:
                st.metric("CVSS", vuln.get("cvss_score", 0))

            if vuln.get("evidence"):
                st.warning(f"📝 Evidencia: {vuln.get('evidence')[:200]}...")
            
            if vuln.get("proof_of_concept"):
                st.code(vuln.get("proof_of_concept"), language="bash")




def render_command_injection_results(parsed, log):
    """Parser para Command Injection Tester"""
    st.markdown("### 💻 Command Injection Detection")

    # Métricas principales
    vulnerable = parsed.get("vulnerable", False)
    vuln_count = parsed.get("vulnerability_count", 0)
    severity = parsed.get("severity", "None")
    confidence = parsed.get("confidence", 0)

    col1, col2, col3 = st.columns(3)

    with col1:
        status_color = "metric-critical" if vulnerable else "metric-low"
        status_text = "🚨 VULNERABLE" if vulnerable else "✅ SEGURO"
        st.markdown(
            f"""
            <div class="metric-card {status_color}">
                <div class="metric-label">ESTADO</div>
                <div class="metric-value">{status_text}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        severity_class_map = {
            "Critical": "metric-critical",
            "High": "metric-high",
            "Medium": "metric-medium",
            "Low": "metric-low",
            "None": "metric-neutral",
        }
        severity_class = severity_class_map.get(severity, "metric-neutral")
        st.markdown(
            f"""
            <div class="metric-card {severity_class}">
                <div class="metric-label">💥 SEVERIDAD</div>
                <div class="metric-value">{severity}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card metric-low">
                <div class="metric-label">📊 CONFIANZA</div>
                <div class="metric-value">{confidence}%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Scan Details
    scan_details = parsed.get("scan_details", {})
    if scan_details:
        st.markdown("---")
        st.markdown("### 📋 Scan Details")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Intentos", scan_details.get("total_attempts", 0))
        with col2:
            st.metric("Bloqueados", scan_details.get("blocked_attempts", 0))
        with col3:
            st.metric("Errores", scan_details.get("error_attempts", 0))
        
        # Tabla de parámetros
        params_tested = scan_details.get("parameters_tested", [])
        if params_tested:
            st.markdown("#### Parámetros Probados")
            
            params_list = []
            for p in params_tested[:10]:
                if isinstance(p, dict):
                    params_list.append({
                        "Parámetro": f"?{p.get('parameter', 'N/A')}=",
                        "Resultado": p.get("result", "N/A").upper(),
                        "Payloads": p.get("payloads_tested", 0)
                    })
                else:
                    params_list.append({
                        "Parámetro": f"?{p}=",
                        "Resultado": "TESTED",
                        "Payloads": 4
                    })
            
            if params_list:
                import pandas as pd
                st.dataframe(pd.DataFrame(params_list), use_container_width=True, hide_index=True)
            
            if len(params_tested) > 10:
                st.info(f"... y {len(params_tested) - 10} parámetros más probados")

    # Protection Analysis
    protection = parsed.get("protection_analysis", {})
    if protection and not vulnerable:
        st.markdown("---")
        st.markdown("### 🛡️  Protection Analysis")
        
        rating = protection.get("security_rating", "Unknown")
        if rating == "Good":
            st.success(f"✅ Security Rating: {rating}")
        elif rating == "Fair":
            st.warning(f"⚠️  Security Rating: {rating}")
        else:
            st.error(f"❌ Security Rating: {rating}")
        
        # Protecciones detectadas
        protections = protection.get("protections_detected", [])
        if protections:
            st.markdown("#### 🔒 Protecciones Detectadas")
            for i, prot in enumerate(protections, 1):
                st.markdown(f"**{i}. {prot['type']} - {prot['confidence']} confidence**")
                st.write(f"📝 {prot['description']}")
                if prot.get("evidence"):
                    st.write(f"🔍 Evidencia: {prot['evidence']}")
                st.markdown("")
        
        # Estadísticas
        stats = protection.get("statistics", {})
        if stats:
            st.markdown("#### 📊 Estadísticas del Scan")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total", stats.get("total_attempts", 0))
            with col2:
                st.metric("Bloqueados", stats.get("blocked", 0))
            with col3:
                st.metric("Errores", stats.get("errors", 0))

    # Vulnerabilidades encontradas
    vulns = parsed.get("vulnerabilities", [])
    if vulns:
        st.markdown("---")
        st.markdown(f"### 🚨 {len(vulns)} Vulnerabilidades Detectadas")

        for vuln in vulns:
            col1, col2 = st.columns([3, 1])
            with col1:
                vuln_type = vuln.get("type", "Command Injection")
                st.error(f"**{vuln.get('severity', 'Critical')} - {vuln_type}** - Parámetro: `{vuln.get('parameter')}`")
                st.caption(f"CWE: **{vuln.get('cwe_id', 'N/A')}** | MITRE: **{vuln.get('mitre_technique_id', 'N/A')}**")
            with col2:
                st.metric("CVSS", vuln.get("cvss_score", 0))

            if vuln.get("evidence"):
                st.warning(f"📝 Evidencia: {vuln.get('evidence')[:200]}...")
            
            if vuln.get("payload"):
                st.markdown("**Payload usado:**")
                st.code(vuln.get("payload"), language="bash")
            
            if vuln.get("proof_of_concept"):
                st.markdown("**Proof of Concept:**")
                st.code(vuln.get("proof_of_concept"), language="bash")


# =====================================================
# DASHBOARD PRINCIPAL
# =====================================================

st.title("🧠 Berebrum Dashboard")
st.markdown("### Plataforma de Red Team con IA")
st.caption("🛡️ OWASP Top 10 | 🔍 Reconocimiento | 🔓 Brute Force")

# =====================================================
# SIDEBAR
# =====================================================
st.sidebar.title("📂 Proyectos")

try:
    projects = db_manager.list_projects(status="active")
except Exception as e:
    st.error(f"Error al cargar proyectos: {e}")
    st.stop()

if not projects:
    st.warning("⚠️ No hay proyectos activos")
    st.code("python -m cli.main", language="bash")
    st.stop()

project_names = {f"{p.name} (ID: {p.id})": p.id for p in projects}
selected_project_name = st.sidebar.selectbox(
    "Seleccionar Proyecto", options=list(project_names.keys())
)

project_id = project_names[selected_project_name]
project = db_manager.get_project(project_id)

st.sidebar.markdown("---")
st.sidebar.markdown("**📋 Información del Proyecto:**")
st.sidebar.text(f"Nombre: {project.name}")
st.sidebar.text(f"Estado: {project.status}")
st.sidebar.text(f"Creado: {format_timestamp(project.created_at, '%d/%m/%y')}")
st.sidebar.markdown(f"**🎯 Scope:**")
st.sidebar.code(project.scope_ips, language=None)

if st.sidebar.button("🔄 Actualizar Datos"):
    st.rerun()

# =====================================================
# TABS
# =====================================================

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📊 Resumen Ejecutivo",
        "📋 Registro de Actividad",
        "🔍 Resultados por Tipo de Ataque",
        "🔴 Vulnerabilidades Críticas",
    ]
)

# =====================================================
# TAB 1: RESUMEN EJECUTIVO
# =====================================================
with tab1:
    st.header("📊 Resumen Ejecutivo del Proyecto")

    stats = db_manager.get_project_stats(project_id)

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f"""
            <div class="metric-card metric-critical">
                <div class="metric-label">🚨 CRÍTICAS</div>
                <div class="metric-value">{stats.get('critical', 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="metric-card metric-high">
                <div class="metric-label">⚠️ ALTAS</div>
                <div class="metric-value">{stats.get('high', 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="metric-card metric-medium">
                <div class="metric-label">🟡 MEDIAS</div>
                <div class="metric-value">{stats.get('medium', 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""
            <div class="metric-card metric-low">
                <div class="metric-label">🟢 BAJAS</div>
                <div class="metric-value">{stats.get('low', 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            f"""
            <div class="metric-card metric-neutral">
                <div class="metric-label">🔧 HERRAMIENTAS</div>
                <div class="metric-value">{stats.get('tools_used', 0)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        if stats.get("total_vulnerabilities", 0) > 0:
            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=["Critical", "High", "Medium", "Low"],
                        values=[
                            stats.get("critical", 0),
                            stats.get("high", 0),
                            stats.get("medium", 0),
                            stats.get("low", 0),
                        ],
                        hole=0.4,
                        marker=dict(
                            colors=["#dc3545", "#fd7e14", "#ffc107", "#28a745"]
                        ),
                    )
                ]
            )
            fig.update_layout(title="Distribución de Vulnerabilidades", height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hay vulnerabilidades detectadas")

    with col2:
        fig = go.Figure(
            data=[
                go.Bar(
                    x=["Exitosos", "Fallidos"],
                    y=[stats.get("successful_logs", 0), stats.get("failed_logs", 0)],
                    marker=dict(color=["#28a745", "#dc3545"]),
                )
            ]
        )
        fig.update_layout(
            title="Ejecuciones de Herramientas", yaxis_title="Cantidad", height=400
        )
        st.plotly_chart(fig, use_container_width=True)

    # =====================================================
    # TIMELINE DE ACTIVIDAD
    # =====================================================
    st.markdown("---")
    st.markdown("### 📈 Timeline de Actividad")

    try:
        logs = db_manager.get_logs(project_id, limit=500)

        if logs and len(logs) > 0:
            # Crear DataFrame para el timeline
            timeline_data = []
            for log in logs:
                timeline_data.append(
                    {
                        "timestamp": log.timestamp,
                        "success": 1 if log.success else 0,
                        "tool": log.tool_name,
                        "category": log.tool_category or "Other",
                    }
                )

            df_timeline = pd.DataFrame(timeline_data)

            # Agrupar por fecha (día)
            df_timeline["date"] = pd.to_datetime(df_timeline["timestamp"]).dt.date
            daily_stats = (
                df_timeline.groupby("date")
                .agg({"success": ["sum", "count"]})
                .reset_index()
            )
            daily_stats.columns = ["date", "successful", "total"]
            daily_stats["failed"] = daily_stats["total"] - daily_stats["successful"]

            # Gráfico de líneas acumulativas
            col1, col2 = st.columns(2)

            with col1:
                # Timeline de éxitos acumulativos
                df_timeline_sorted = df_timeline.sort_values("timestamp")
                df_timeline_sorted["cumulative_success"] = df_timeline_sorted[
                    "success"
                ].cumsum()

                fig_timeline = px.line(
                    df_timeline_sorted,
                    x="timestamp",
                    y="cumulative_success",
                    title="Ejecuciones Exitosas Acumuladas",
                    labels={
                        "cumulative_success": "Total Exitosas",
                        "timestamp": "Fecha",
                    },
                )
                fig_timeline.update_traces(line_color="#28a745")
                fig_timeline.update_layout(height=350)
                st.plotly_chart(fig_timeline, use_container_width=True)

            with col2:
                # Actividad por categoría
                category_stats = (
                    df_timeline.groupby("category")["success"].sum().reset_index()
                )
                category_stats.columns = ["category", "count"]

                fig_category = px.bar(
                    category_stats,
                    x="category",
                    y="count",
                    title="Actividad por Categoría",
                    labels={"count": "Ejecuciones", "category": "Categoría"},
                    color="count",
                    color_continuous_scale="Blues",
                )
                fig_category.update_layout(height=350, showlegend=False)
                st.plotly_chart(fig_category, use_container_width=True)

            # Tabla de actividad reciente
            st.markdown("#### 📋 Actividad Reciente (Últimas 10 ejecuciones)")
            recent_logs = logs[:10]
            recent_data = []
            for log in recent_logs:
                recent_data.append(
                    {
                        "✅/❌": "✅" if log.success else "❌",
                        "🔧 Herramienta": log.tool_name,
                        "🎯 Target": (
                            log.target[:40] + "..."
                            if len(log.target) > 40
                            else log.target
                        ),
                        "⏱️ Duración": format_duration(log.duration_seconds),
                        "📅 Fecha": format_timestamp(log.timestamp, "%d/%m/%y %H:%M"),
                    }
                )

            df_recent = pd.DataFrame(recent_data)
            st.dataframe(df_recent, use_container_width=True, hide_index=True)

        else:
            st.info("No hay suficiente actividad para generar el timeline")

    except Exception as e:
        st.error(f"Error al generar timeline: {str(e)}")
        st.info("Ejecuta algunas herramientas para ver la actividad")

# =====================================================
# TAB 2: LOGS
# =====================================================
with tab2:
    st.header("📋 Registro de Actividad")

    logs = db_manager.get_logs(project_id, limit=100)

    if not logs:
        st.info("No hay actividad registrada")
    else:
        # =====================================================
        # BOTONES DE DESCARGA
        # =====================================================
        st.markdown("### 💾 Exportar Logs")

        col1, col2, col3 = st.columns(3)

        # Preparar datos para descarga
        logs_data = []
        for log in logs:
            logs_data.append(
                {
                    "Fecha": format_timestamp(log.timestamp, "%Y-%m-%d %H:%M:%S"),
                    "Herramienta": log.tool_name,
                    "Categoría": log.tool_category or "N/A",
                    "Target": log.target,
                    "Estado": "Exitoso" if log.success else "Fallido",
                    "Duración (s)": log.duration_seconds or 0,
                    "Output": log.output or "",
                }
            )

        df_logs = pd.DataFrame(logs_data)

        with col1:
            # Descarga CSV
            csv = df_logs.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Descargar CSV",
                data=csv,
                file_name=f"berebrum_logs_{project.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
                key="download_logs_csv",
            )

        with col2:
            # Descarga JSON
            import json

            json_data = df_logs.to_json(orient="records", indent=2)
            st.download_button(
                label="📥 Descargar JSON",
                data=json_data,
                file_name=f"berebrum_logs_{project.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
                key="download_logs_json",
            )

        with col3:
            # Descarga Excel (con manejo de error si openpyxl no está)
            try:
                from io import BytesIO

                buffer = BytesIO()
                with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
                    df_logs.to_excel(writer, sheet_name="Logs", index=False)

                st.download_button(
                    label="📥 Descargar Excel",
                    data=buffer.getvalue(),
                    file_name=f"berebrum_logs_{project.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    key="download_logs_excel",
                )
            except ImportError:
                st.button(
                    "📥 Descargar Excel",
                    disabled=True,
                    help="Instala openpyxl: pip install openpyxl",
                    use_container_width=True,
                    key="excel_logs_disabled",
                )

        st.markdown("---")

        # =====================================================
        # FILTROS
        # =====================================================

        col1, col2, col3 = st.columns(3)

        with col1:
            tools_filter = st.multiselect(
                "Filtrar por Herramienta",
                options=list(set(log.tool_name for log in logs if log.tool_name)),
                default=[],
            )

        with col2:
            success_filter = st.selectbox(
                "Estado", options=["Todos", "Exitosos", "Fallidos"]
            )

        with col3:
            category_filter = st.multiselect(
                "Categoría",
                options=list(
                    set(log.tool_category for log in logs if log.tool_category)
                ),
                default=[],
            )

        filtered_logs = logs

        if tools_filter:
            filtered_logs = [
                log for log in filtered_logs if log.tool_name in tools_filter
            ]

        if success_filter == "Exitosos":
            filtered_logs = [log for log in filtered_logs if log.success]
        elif success_filter == "Fallidos":
            filtered_logs = [log for log in filtered_logs if not log.success]

        if category_filter:
            filtered_logs = [
                log for log in filtered_logs if log.tool_category in category_filter
            ]

        st.caption(f"Mostrando {len(filtered_logs)} de {len(logs)} registros")

        for log in filtered_logs[:20]:
            with st.expander(
                f"{'✅' if log.success else '❌'} {TOOL_ICONS.get(log.tool_name, '🔧')} {log.tool_name} - {log.target} ({format_timestamp(log.timestamp, '%d/%m/%y %H:%M')})"
            ):
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown(f"**🎯 Target:** `{log.target}`")
                    st.markdown(
                        f"**⏱️ Duración:** {format_duration(log.duration_seconds)}"
                    )
                    st.markdown(
                        f"**📅 Fecha:** {format_timestamp(log.timestamp, '%d/%m/%Y %H:%M:%S')}"
                    )

                with col2:
                    st.markdown(f"**🔧 Herramienta:** {log.tool_name}")
                    st.markdown(f"**📂 Categoría:** {log.tool_category or 'N/A'}")
                    st.markdown(
                        f"**✅ Estado:** {'Exitoso' if log.success else 'Fallido'}"
                    )

# =====================================================
# TAB 3: RESULTADOS POR TIPO DE ATAQUE
# =====================================================
with tab3:
    st.header("🔍 Resultados por Tipo de Ataque")

    logs = db_manager.get_logs(project_id, limit=1000)

    if not logs:
        st.info("No hay resultados disponibles")
    else:
        # Selector por categoría
        st.markdown("### Selecciona el Tipo de Ataque:")

        category_tabs = st.tabs(
            [
                f"{cat_info['icon']} {cat_name}"
                for cat_name, cat_info in TOOL_CATEGORIES.items()
            ]
        )

        for idx, (cat_name, cat_info) in enumerate(TOOL_CATEGORIES.items()):
            with category_tabs[idx]:
                # Filtrar herramientas de esta categoría
                available_tools = [
                    t
                    for t in cat_info["tools"]
                    if any(log.tool_name == t for log in logs)
                ]

                if not available_tools:
                    st.info(f"No hay resultados de herramientas de {cat_name}")
                    continue

                # Selector de herramienta dentro de la categoría
                selected_tool = st.radio(
                    f"Herramientas de {cat_name}:",
                    options=[f"{TOOL_ICONS.get(t, '🔧')} {t}" for t in available_tools],
                    label_visibility="collapsed",
                )

                tool_name = (
                    selected_tool.split(" ", 1)[1]
                    if " " in selected_tool
                    else selected_tool
                )
                tool_logs = [log for log in logs if log.tool_name == tool_name]

                st.markdown("---")
                st.subheader(f"{TOOL_ICONS.get(tool_name, '🔧')} {tool_name}")
                st.markdown(
                    f'<span class="{cat_info["badge"]}">{cat_info["icon"]} {cat_name}</span>',
                    unsafe_allow_html=True,
                )
                st.caption(f"{len(tool_logs)} ejecuciones encontradas")

                # Mostrar resultados
                for log in tool_logs[:10]:
                    # Parsear output una sola vez
                    parsed = safe_json_parse(log.output)

                    # ==================================================
                    # PREVIEW CARD - VISIBLE SIN EXPANDIR
                    # ==================================================

                    # Crear preview según herramienta
                    preview_html = ""

                    if tool_name == "SQL Injection Scanner" and parsed:
                        vuln = parsed.get("vulnerable", False)
                        db_type = parsed.get("database_type", "Unknown")
                        conf = parsed.get("confidence", 0)
                        vuln_count = len(parsed.get("vulnerabilities", []))

                        status_color = "#dc3545" if vuln else "#28a745"
                        status_text = "🚨 VULNERABLE" if vuln else "✅ SEGURO"

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {status_color};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span style="font-size: 18px; font-weight: bold; color: {status_color};">{status_text}</span>
                                    <span style="margin-left: 15px; color: #aaa;">🗄️ {db_type}</span>
                                    <span style="margin-left: 15px; color: #aaa;">📊 {conf}% confianza</span>
                                    {f'<span style="margin-left: 15px; color: #fd7e14;">🚨 {vuln_count} vulnerabilidades</span>' if vuln_count > 0 else ''}
                                </div>
                            </div>
                        </div>
                        """

                    elif tool_name == "Port Scanner" and parsed:
                        open_ports = parsed.get("open_ports", []) or []
                        ports_count = len(open_ports)

                        status_color = "#fd7e14" if ports_count > 0 else "#28a745"

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {status_color};">
                            <div style="display: flex; gap: 20px; align-items: center;">
                                <span style="font-size: 24px; font-weight: bold; color: {status_color};">{ports_count}</span>
                                <span style="color: #fff;">puertos abiertos detectados</span>
                                {f'<span style="color: #aaa;">Servicios: {", ".join([p.get("service", "?") for p in open_ports[:3]])}{"..." if ports_count > 3 else ""}</span>' if ports_count > 0 else ''}
                            </div>
                        </div>
                        """

                    elif tool_name == "SSL/TLS Analyzer" and parsed:
                        valid = parsed.get("valid_certificate", False)
                        expires = parsed.get("expires_in_days") or 0
                        version = parsed.get("tls_version") or "N/A"

                        status_color = (
                            "#28a745" if valid and expires > 30 else "#dc3545"
                        )
                        status_text = "✅ Válido" if valid else "❌ Inválido"
                        expires_color = "#dc3545" if expires < 30 else "#28a745"

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {status_color};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span style="font-size: 18px; font-weight: bold; color: {status_color};">🔒 {status_text}</span>
                                    <span style="margin-left: 20px; color: {expires_color}; font-weight: bold;">
                                        ⏰ Expira en {expires} días {' ⚠️ RENOVAR URGENTE' if expires < 30 else ''}
                                    </span>
                                    <span style="margin-left: 20px; color: #aaa;">📡 TLS {version}</span>
                                </div>
                            </div>
                        </div>
                        """

                    elif tool_name in ["SSH Brute Force", "FTP Brute Force"] and parsed:
                        credentials_found = parsed.get("credentials_found", []) or []
                        total_attempts = parsed.get("total_attempts", 0) or 0
                        creds_count = len(credentials_found)

                        status_color = "#dc3545" if creds_count > 0 else "#28a745"
                        status_text = (
                            f"🚨 {creds_count} CREDENCIALES COMPROMETIDAS"
                            if creds_count > 0
                            else "✅ SEGURO"
                        )

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {status_color};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span style="font-size: 18px; font-weight: bold; color: {status_color};">{status_text}</span>
                                    <span style="margin-left: 20px; color: #aaa;">🔢 {total_attempts} intentos</span>
                                </div>
                            </div>
                        </div>
                        """

                    elif tool_name == "Subdomain Enumerator" and parsed:
                        subdomains = parsed.get("subdomains", []) or []
                        count = len(subdomains)
                        active = len(
                            [s for s in subdomains if s.get("status") == "active"]
                        )

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #17a2b8;">
                            <div style="display: flex; gap: 20px; align-items: center;">
                                <span style="font-size: 24px; font-weight: bold; color: #17a2b8;">{count}</span>
                                <span style="color: #fff;">subdominios encontrados</span>
                                <span style="color: #28a745;">✅ {active} activos</span>
                            </div>
                        </div>
                        """

                    elif tool_name == "Web Directory Scanner" and parsed:
                        found_dirs = parsed.get("found_directories", []) or []
                        count = len(found_dirs)
                        sensitive = len(
                            [d for d in found_dirs if d.get("sensitive", False)]
                        )

                        status_color = "#fd7e14" if sensitive > 0 else "#17a2b8"

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {status_color};">
                            <div style="display: flex; gap: 20px; align-items: center;">
                                <span style="font-size: 24px; font-weight: bold; color: #17a2b8;">{count}</span>
                                <span style="color: #fff;">directorios encontrados</span>
                                {f'<span style="color: #fd7e14;">🚨 {sensitive} sensibles</span>' if sensitive > 0 else '<span style="color: #28a745;">✅ ninguno sensible</span>'}
                            </div>
                        </div>
                        """

                    elif tool_name == "HTTP Header Analyzer" and parsed:
                        security_headers = parsed.get("security_headers", {})
                        missing = len([h for h, v in security_headers.items() if not v])

                        status_color = "#dc3545" if missing > 0 else "#28a745"
                        status_text = (
                            f"⚠️ {missing} headers de seguridad faltantes"
                            if missing > 0
                            else "✅ Todos los headers presentes"
                        )

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid {status_color};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 18px; font-weight: bold; color: {status_color};">{status_text}</span>
                            </div>
                        </div>
                        """

                    elif tool_name == "Banner Grabber" and parsed:
                        banners = parsed.get("banners", []) or []
                        count = len(banners)

                        preview_html = f"""
                        <div style="background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%); 
                                    padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #17a2b8;">
                            <div style="display: flex; gap: 20px; align-items: center;">
                                <span style="font-size: 24px; font-weight: bold; color: #17a2b8;">{count}</span>
                                <span style="color: #fff;">servicios identificados</span>
                            </div>
                        </div>
                        """

                    # Mostrar preview card
                    if preview_html:
                        st.markdown(preview_html, unsafe_allow_html=True)

                    # ==================================================
                    # EXPANDER CON DETALLES COMPLETOS
                    # ==================================================
                    with st.expander(
                        f"{'✅' if log.success else '❌'} Ver detalles completos · Target: {log.target} | {format_timestamp(log.timestamp, '%d/%m/%y %H:%M')}"
                    ):
                        if not parsed:
                            st.warning("No hay datos disponibles para mostrar")
                            continue

                        # Router a parser específico
                        if tool_name == "SQL Injection Scanner":
                            render_sql_injection_results(parsed, log)
                        elif tool_name == "Port Scanner":
                            render_port_scanner_results(parsed, log)
                        elif tool_name == "Subdomain Enumerator":
                            render_subdomain_results(parsed, log)
                        elif tool_name == "Web Directory Scanner":
                            render_directory_scanner_results(parsed, log)
                        elif tool_name == "Banner Grabber":
                            render_banner_grabber_results(parsed, log)
                        elif tool_name == "HTTP Header Analyzer":
                            render_http_header_results(parsed, log)
                        elif tool_name == "DNS Information Gatherer":
                            render_dns_results(parsed, log)
                        elif tool_name == "SSL/TLS Analyzer":
                            render_ssl_tls_results(parsed, log)
                        elif tool_name in ["SSH Brute Force", "FTP Brute Force"]:
                            render_brute_force_results(parsed, log, tool_name)
                        elif tool_name == "SSTI Detector":
                            render_ssti_results(parsed, log)
                        elif tool_name == "LFI/RFI Scanner":
                            render_lfi_rfi_results(parsed, log)
                        else:
                            # Fallback: mostrar solo métricas básicas
                            st.info(f"✅ Escaneo completado exitosamente")
                            if "total" in parsed:
                                st.metric("Total Items", parsed.get("total"))

# =====================================================
# TAB 4: VULNERABILIDADES
# =====================================================
with tab4:
    st.header("🔴 Vulnerabilidades Críticas")

    vulns = db_manager.get_vulnerabilities(project_id)

    if not vulns:
        st.success("✅ No se han detectado vulnerabilidades críticas")
    else:
        # =====================================================
        # BOTONES DE DESCARGA DE REPORTE
        # =====================================================
        st.markdown("### 💾 Exportar Reporte de Vulnerabilidades")

        col1, col2, col3 = st.columns(3)

        # Preparar datos con TODOS los campos disponibles
        vuln_data = []
        for vuln in vulns:
            vuln_data.append(
                {
                    "Fecha": format_timestamp(vuln.discovered_at, "%Y-%m-%d %H:%M:%S"),
                    "Título": vuln.title or "N/A",
                    "Severidad": vuln.severity or "N/A",
                    "CVSS": vuln.cvss_score or 0,
                    "CVSS Vector": vuln.cvss_vector or "N/A",
                    "Target": vuln.target or "N/A",
                    "Puerto": vuln.port or "N/A",
                    "Servicio": vuln.service or "N/A",
                    "CVE": vuln.cve_id or "N/A",
                    "CWE": vuln.cwe_id or "N/A",
                    "MITRE Tactic": vuln.mitre_tactic or "N/A",
                    "MITRE Technique ID": vuln.mitre_technique_id or "N/A",
                    "MITRE Technique": vuln.mitre_technique_name or "N/A",
                    "Descripción": vuln.description or "",
                    "PoC": vuln.proof_of_concept or "",
                    "Remediación": vuln.remediation or "",
                    "False Positive": "Sí" if vuln.false_positive else "No",
                }
            )

        df_vulns = pd.DataFrame(vuln_data)

        with col1:
            # CSV
            csv = df_vulns.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Descargar CSV",
                data=csv,
                file_name=f"berebrum_vulnerabilities_{project.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
                key="download_vulns_csv",
            )

        with col2:
            # JSON
            import json

            json_data = df_vulns.to_json(orient="records", indent=2)
            st.download_button(
                label="📥 Descargar JSON",
                data=json_data,
                file_name=f"berebrum_vulnerabilities_{project.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
                key="download_vulns_json",
            )

        with col3:
            # Excel
            try:
                from io import BytesIO

                buffer = BytesIO()
                with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
                    df_vulns.to_excel(
                        writer, sheet_name="Vulnerabilidades", index=False
                    )

                st.download_button(
                    label="📥 Descargar Excel",
                    data=buffer.getvalue(),
                    file_name=f"berebrum_vulnerabilities_{project.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True,
                    key="download_vulns_excel",
                )
            except ImportError:
                st.button(
                    "📥 Descargar Excel",
                    disabled=True,
                    help="Instala openpyxl: pip install openpyxl",
                    use_container_width=True,
                    key="excel_vulns_disabled",
                )

        st.markdown("---")

        # =====================================================
        # FILTROS
        # =====================================================

        col1, col2 = st.columns(2)

        with col1:
            severity_filter = st.multiselect(
                "Severidad",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"],
            )

        with col2:
            min_cvss = st.slider("CVSS Mínimo", 0.0, 10.0, 0.0, 0.1)

        filtered_vulns = [
            v
            for v in vulns
            if v.severity in severity_filter and (v.cvss_score or 0) >= min_cvss
        ]

        st.caption(f"Mostrando {len(filtered_vulns)} de {len(vulns)} vulnerabilidades")

        for vuln in filtered_vulns:
            severity_class_map = {
                "Critical": "vuln-critical",
                "High": "vuln-high",
                "Medium": "vuln-medium",
                "Low": "vuln-low",
            }
            card_class = severity_class_map.get(vuln.severity, "vuln-low")

            emoji_map = {"Critical": "🚨", "High": "⚠️", "Medium": "🟡", "Low": "🟢"}
            emoji = emoji_map.get(vuln.severity, "🔵")

            severity_badge = f'<span class="severity-badge {vuln.severity.lower()}">{vuln.severity.upper()}</span>'

            cvss_score = vuln.cvss_score or 0
            st.markdown(
                f"""
<div class="vuln-card {card_class}">
    <h4>{emoji} {vuln.title}</h4>
    <p>{severity_badge}</p>
    <p><strong>Target:</strong> <code>{vuln.target}</code></p>
    <p><strong>CVSS:</strong> {cvss_score:.1f}/10.0</p>
    <p>{vuln.description or 'Sin descripción'}</p>
</div>
""",
                unsafe_allow_html=True,
            )

st.markdown("---")
st.caption("🧠 Berebrum - Plataforma de Red Team con IA v2.0")
