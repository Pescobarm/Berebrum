"""
Berebrum Dashboard - Style Loader
Módulo para cargar CSS desde archivo externo
"""

import streamlit as st
from pathlib import Path


def load_custom_styles():
    """
    Carga los estilos CSS desde archivo externo

    Si el archivo no existe, carga estilos embebidos como fallback
    """
    # Buscar archivo CSS en diferentes ubicaciones
    possible_paths = [
        Path(__file__).parent / "dashboard_styles.css",  # Mismo directorio
        Path(__file__).parent.parent
        / "dashboard"
        / "dashboard_styles.css",  # Directorio dashboard
        Path(__file__).parent.parent / "dashboard_styles.css",  # Directorio raíz
    ]

    css_loaded = False

    for css_path in possible_paths:
        if css_path.exists():
            try:
                with open(css_path, "r", encoding="utf-8") as f:
                    css_content = f.read()

                st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)
                css_loaded = True
                print(f"✅ CSS cargado desde: {css_path}")
                break
            except Exception as e:
                print(f"⚠️ Error al cargar CSS desde {css_path}: {e}")
                continue

    # Fallback si no se encuentra el archivo
    if not css_loaded:
        print("⚠️ CSS externo no encontrado, usando fallback embebido")
        load_fallback_styles()


def load_fallback_styles():
    """
    Estilos embebidos como fallback si no se encuentra el archivo CSS
    """
    st.markdown(
        """
    <style>
    .severity-badge { padding: 4px 12px; border-radius: 12px; font-weight: bold; }
    .critical { background-color: #dc3545; color: white; }
    .high { background-color: #fd7e14; color: white; }
    .medium { background-color: #ffc107; color: black; }
    .low { background-color: #28a745; color: white; }
    .metric-card { padding: 20px; border-radius: 10px; text-align: center; color: white; }
    </style>
    """,
        unsafe_allow_html=True,
    )
