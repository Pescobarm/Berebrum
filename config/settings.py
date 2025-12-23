import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables del archivo .env
load_dotenv()

# Rutas Base
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
WORDLISTS_DIR = DATA_DIR / "wordlists"
OUTPUT_DIR = BASE_DIR / "outputs"

# Configuración de Base de Datos
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///berebrum.db")

# Configuración de Diccionarios
DICT_REPO_URL = os.getenv(
    "DICT_REPO_URL", "https://github.com/hackingyseguridad/diccionarios.git"
)

# Crear directorios necesarios si no existen
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
