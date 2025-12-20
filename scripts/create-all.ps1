# scripts/create-all.ps1
# Script maestro para crear Berebrum - VERSIÓN CORREGIDA

param(
    [switch]$Docker = $false
)

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        🧠 Berebrum - Instalación Automática               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Docker) {
    Write-Host "Modo: Docker 🐳" -ForegroundColor Blue
} else {
    Write-Host "Modo: PowerShell 💻" -ForegroundColor Blue
}
Write-Host ""

# ============== README.md ==============
Write-Host "[1/20] Creando README.md..." -ForegroundColor Yellow

$readmeContent = @'
# 🧠 Berebrum - AI-Powered Red Team Platform

## ⚠️ DISCLAIMER
**Esta herramienta es EXCLUSIVAMENTE para uso educativo y pentesting autorizado.**
El uso no autorizado es ILEGAL y puede resultar en consecuencias penales.

## 📋 Características

- ✅ Integración con MITRE ATT&CK Framework
- ✅ Scoring automático CVSS v3.1
- ✅ Orquestación basada en MCP
- ✅ Motor de decisión con IA
- ✅ Dashboard web interactivo
- ✅ Validación de scope automática
- ✅ Soporte Docker y Windows

## 🚀 Instalación

### Opción 1: Docker (Recomendado)
```powershell
# Windows PowerShell
docker-compose up -d
```
```bash
# Linux/Mac
docker-compose up -d
```

Dashboard: http://localhost:8501

### Opción 2: Windows PowerShell
```powershell
.\scripts\install-windows.ps1
```

### Opción 3: Linux/Mac
```bash
chmod +x scripts/install-linux.sh
./scripts/install-linux.sh
```

## 🎯 Uso

### Windows
```powershell
.\venv\Scripts\Activate.ps1
python cli\main.py
```

### Linux/Mac
```bash
source venv/bin/activate
python cli/main.py
```

### Docker
```bash
docker-compose logs -f
docker-compose exec berebrum-cli python cli/main.py
```

## 📂 Estructura
```
berebrum/
├── core/              # Núcleo del sistema
├── mcp/               # Protocolo MCP
├── tools/             # Arsenal de herramientas
├── utils/             # Utilidades (CVSS, MITRE)
├── cli/               # Interfaz CLI
├── dashboard/         # Dashboard web
└── scripts/           # Scripts de instalación
```

## 📜 Licencia
MIT License - Solo uso ético y autorizado
'@

Set-Content -Path "README.md" -Value $readmeContent -Encoding UTF8
Write-Host "✓ README.md creado" -ForegroundColor Green

# ============== requirements.txt ==============
Write-Host "[2/20] Creando requirements.txt..." -ForegroundColor Yellow

$requirementsContent = @'
# Berebrum Dependencies
# Python 3.10+

sqlalchemy==2.0.23
InquirerPy==0.3.4
rich==13.7.0
streamlit==1.29.0
plotly==5.18.0
pandas==2.1.4
fastapi==0.109.0
uvicorn[standard]==0.25.0
pydantic==2.5.3
requests==2.31.0
dnspython==2.4.2
pyyaml==6.0.1
python-dotenv==1.0.0
loguru==0.7.2
pytest==7.4.3
'@

Set-Content -Path "requirements.txt" -Value $requirementsContent -Encoding UTF8
Write-Host "✓ requirements.txt creado" -ForegroundColor Green

# ============== Dockerfile ==============
Write-Host "[3/20] Creando Dockerfile..." -ForegroundColor Yellow

$dockerfileContent = @'
FROM python:3.11-slim

LABEL maintainer="Berebrum Team"
LABEL description="AI-Powered Red Team Platform"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 berebrum && \
    mkdir -p /app /data /logs /database && \
    chown -R berebrum:berebrum /app /data /logs /database

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=berebrum:berebrum . .

USER berebrum

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=10s \
    CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "cli/main.py"]
'@

Set-Content -Path "Dockerfile" -Value $dockerfileContent -Encoding UTF8
Write-Host "✓ Dockerfile creado" -ForegroundColor Green

# ============== docker-compose.yml ==============
Write-Host "[4/20] Creando docker-compose.yml..." -ForegroundColor Yellow

$dockerComposeContent = @'
version: '3.8'

services:
  berebrum-cli:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: berebrum_cli
    stdin_open: true
    tty: true
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - berebrum_db:/app/database
    networks:
      - berebrum_net
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped

  berebrum-dashboard:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: berebrum_dashboard
    ports:
      - "8501:8501"
    volumes:
      - ./data:/app/data
      - berebrum_db:/app/database
    networks:
      - berebrum_net
    command: streamlit run dashboard/app.py --server.port=8501 --server.address=0.0.0.0
    restart: unless-stopped
    depends_on:
      - berebrum-cli

networks:
  berebrum_net:
    driver: bridge

volumes:
  berebrum_db:
    driver: local
'@

Set-Content -Path "docker-compose.yml" -Value $dockerComposeContent -Encoding UTF8
Write-Host "✓ docker-compose.yml creado" -ForegroundColor Green

# ============== .gitignore ==============
Write-Host "[5/20] Creando .gitignore..." -ForegroundColor Yellow

$gitignoreContent = @'
__pycache__/
*.py[cod]
venv/
env/
*.db
*.sqlite3
database/
logs/
*.log
data/
.env
.vscode/
.idea/
*.swp
.DS_Store
reports/
*.pdf
'@

Set-Content -Path ".gitignore" -Value $gitignoreContent -Encoding UTF8
Write-Host "✓ .gitignore creado" -ForegroundColor Green

# ============== .dockerignore ==============
Write-Host "[6/20] Creando .dockerignore..." -ForegroundColor Yellow

$dockerignoreContent = @'
.git
.gitignore
__pycache__
*.pyc
venv/
env/
*.db
database/
logs/
data/
.vscode/
.idea/
*.md
docs/
.pytest_cache/
tests/
'@

Set-Content -Path ".dockerignore" -Value $dockerignoreContent -Encoding UTF8
Write-Host "✓ .dockerignore creado" -ForegroundColor Green

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✓ Archivos base creados exitosamente!                    ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Siguiente paso:" -ForegroundColor Cyan
Write-Host "  .\scripts\create-core.ps1" -ForegroundColor White
Write-Host ""