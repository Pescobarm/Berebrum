# Berebrum - AI-Powered Red Team Platform

## DISCLAIMER
Esta herramienta es EXCLUSIVAMENTE para uso educativo y pentesting autorizado.
El uso no autorizado es ILEGAL.

## Caracteristicas

- Integracion con MITRE ATT&CK Framework
- Scoring automatico CVSS v3.1
- Orquestacion basada en MCP
- Motor de decision con IA
- Dashboard web interactivo
- Validacion de scope automatica

## Instalacion

### Windows PowerShell
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python setup.py
```

### Docker
```bash
docker-compose up -d
```

## Uso
```powershell
# CLI
python cli\main.py

# Dashboard
streamlit run dashboard\app.py
```contribucion de yo
