# scripts/install-windows.ps1
Write-Host ""
Write-Host "🧠 Berebrum - Instalación para Windows" -ForegroundColor Cyan
Write-Host ""

# Verificar Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python no está instalado" -ForegroundColor Red
    Write-Host "   Descarga desde: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Python encontrado" -ForegroundColor Green
python --version

# Crear entorno virtual
Write-Host ""
Write-Host "Creando entorno virtual..." -ForegroundColor Yellow
python -m venv venv

# Activar entorno
Write-Host "Activando entorno virtual..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Instalar dependencias
Write-Host "Instalando dependencias..." -ForegroundColor Yellow
pip install --upgrade pip
pip install -r requirements.txt

# Ejecutar setup
Write-Host "Ejecutando setup..." -ForegroundColor Yellow
python setup.py

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✓ Instalación completada!                                ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Para usar Berebrum:" -ForegroundColor Cyan
Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "  python cli\main.py" -ForegroundColor White