# Crear script de Linux (desde PowerShell)
$linuxInstallContent = @'
#!/bin/bash
# scripts/install-linux.sh

echo ""
echo "🧠 Berebrum - Instalación para Linux/Mac"
echo ""

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado"
    exit 1
fi

echo "✓ Python encontrado"
python3 --version

# Crear entorno virtual
echo ""
echo "Creando entorno virtual..."
python3 -m venv venv

# Activar entorno
echo "Activando entorno virtual..."
source venv/bin/activate

# Instalar dependencias
echo "Instalando dependencias..."
pip install --upgrade pip
pip install -r requirements.txt

# Ejecutar setup
echo "Ejecutando setup..."
python setup.py

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  ✓ Instalación completada!                                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Para usar Berebrum:"
echo "  source venv/bin/activate"
echo "  python cli/main.py"
'@

Set-Content -Path "scripts\install-linux.sh" -Value $linuxInstallContent -Encoding UTF8