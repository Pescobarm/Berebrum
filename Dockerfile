# Usamos una imagen base ligera de Python
FROM python:3.10-slim

# 1. Instalar herramientas del sistema (El Arsenal Base)
# nmap: Para escaneos
# graphviz: Para los mapas de red
# iputils-ping: Para pruebas de red
# gcc & libpq-dev: Para compilar librerías si fuera necesario
RUN apt-get update && apt-get install -y \
    nmap \
    graphviz \
    iputils-ping \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Configurar directorio de trabajo
WORKDIR /app

# 3. Copiar dependencias e instalar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copiar todo el código fuente al contenedor
COPY . .

# 5. Exponer puertos
# 8501: Streamlit Dashboard
# 5000: API (Futuro)
EXPOSE 8501
EXPOSE 5000

# 6. Comando por defecto (Mantiene el contenedor vivo)
# Usaremos 'docker-compose' para lanzar el main.py interactivo
CMD ["tail", "-f", "/dev/null"]