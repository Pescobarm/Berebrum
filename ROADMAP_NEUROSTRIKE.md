# 🧠 NeuroStrike Hub - Roadmap Maestro & Arquitectura

**Versión:** 1.0.0  
**Rol:** Lead Security Architect / DevSecOps  
**Objetivo:** Construir una plataforma de orquestación de pentesting ofensivo, modular, basada en estándares MCP y potenciasa por IA.

---

## 🏗️ Arquitectura de Alto Nivel

El sistema se basa en 3 pilares fundamentales:
1.  **Arsenal (Tools):** Herramientas de RedTeam y OWASP estandarizadas como "Servidores MCP".
2.  **Cerebro (Logic):** Motor de decisión (inicialmente manual/lógica, finalmente IA HexStrike).
3.  **Datos (Memory):** Base de datos relacional que almacena no solo hallazgos, sino el **Attack Flow** completo.

### Concepto Clave: "The Attack Flow"
Para permitir la reproducción manual y la auditoría, cada acción se guarda como un nodo en una cadena de eventos:
> `Scope` -> `Recon (Nmap)` -> `Finding (Port 80)` -> `Enumeration (Fuzzing)` -> `Finding (LFI)` -> `Exploit (RCE)`

---

## 🚀 Fases de Desarrollo (Sprints)

### 🏁 Fase 1: Cimientos (Architecture & Data)
*Objetivo: Estructura base, base de datos y validación de seguridad (Safety Rails).*

- [ ] **1.1 Estructura de Proyecto:** Definir carpetas (`core`, `mcp_servers`, `database`, `config`).
- [ ] **1.2 Entorno Local (VSCode/PowerShell):** Configuración de `requirements.txt`, variables de entorno y scripts de inicio.
- [ ] **1.3 Modelado de Datos (SQLAlchemy):**
    - [ ] Tabla `Projects` (Scope, Configuración).
    - [ ] Tabla `Findings` (Con campos MITRE ATT&CK y CVSS 3.1/4.0).
    - [ ] Tabla `AttackFlow` (Registro de comandos, logs crudos y relación padre-hijo de las acciones).
- [ ] **1.4 Safety Rail (El Guardián):** Sistema inviolable que impide peticiones a IPs/Dominios fuera del Scope definido.

### 🔧 Fase 2: El Motor (Core Engine)
*Objetivo: Gestión de recursos externos y protocolo de comunicación.*

- [ ] **2.1 Dictionary Manager:**
    - [ ] Integración con `hackingyseguridad/diccionarios`.
    - [ ] Lógica de clonado automático y actualización (`gitpython`).
    - [ ] Sistema de mapeo (Alias -> Ruta de archivo) para desacoplar las herramientas de los archivos de texto.
- [ ] **2.2 Protocolo MCP Base:**
    - [ ] Clase `MCPTool` abstracta.
    - [ ] Estandarización de `Input` (Argumentos) y `Output` (JSON parseado).
    - [ ] Manejo de errores y Timeouts.
- [ ] **2.3 Evidence Collector:** Utilitario para guardar capturas, logs crudos y archivos descargados organizados por proyecto.

### 🛠️ Fase 3: El Arsenal (Implementación de MCPs)
*Objetivo: Portar y envolver herramientas de RedTeamTools.*

- [ ] **3.1 Reconnaissance (Reconocimiento):**
    - [ ] Wrapper `Nmap` (Discovery & Service detection).
    - [ ] Wrapper `Wappalyzer` (Tech Stack identification).
- [ ] **3.2 Web OWASP:**
    - [ ] **LFI/RFI Refactorizado:** Usando el `Dictionary Manager`.
    - [ ] **SSTI:** Integración de wrappers para `tplmap`/`sstimap`.
    - [ ] **XSS Reflected:** Scanner con payloads de políglotas.
- [ ] **3.3 Brute Force:**
    - [ ] Wrapper `Hydra` (Soporte modular para SSH, FTP, RDP).
- [ ] **3.4 Utils & Mobile:**
    - [ ] Wrappers básicos de ADB y análisis estático.

### 🖥️ Fase 4: Interfaz de Mando (CLI & UX)
*Objetivo: Control total desde la terminal (PowerShell/Bash).*

- [ ] **4.1 Menú Interactivo (InquirerPy):**
    - [ ] Wizard de creación de proyecto y definición de Scope.
    - [ ] Selector de herramientas modular.
- [ ] **4.2 Visualización en Terminal:**
    - [ ] Tablas de progreso y hallazgos en tiempo real (librería `Rich`).
    - [ ] Logs coloreados por severidad.

### 📊 Fase 5: Dashboard & Reporte
*Objetivo: Visualizar la data para la toma de decisiones.*

- [ ] **5.1 API Layer:** Pequeña capa de acceso a la BD SQLite/Postgres.
- [ ] **5.2 Dashboard (Streamlit):**
    - [ ] Matriz de Riesgo (Heatmap MITRE).
    - [ ] **Attack Flow Visualizer:** Gráfico de nodos que muestra la ruta de ataque.
    - [ ] Buscador de vulnerabilidades por CVSS.
- [ ] **5.3 Exportador:** Generación de reporte técnico básico (Markdown/PDF) con pasos de reproducción.

### 🧠 Fase 6: Evolución (AI & Docker)
*Objetivo: Automatización inteligente y despliegue final.*

- [ ] **6.1 Integración "Cerebro" (HexStrike Logic):**
    - [ ] Agente que analiza el `AttackFlow` y sugiere el siguiente módulo MCP.
    - [ ] Integración con LLMs (OpenAI/Local) para análisis de logs complejos.
- [ ] **6.2 Dockerización Completa:**
    - [ ] `Dockerfile` optimizado con todas las dependencias de sistema.
    - [ ] `docker-compose.yml` para levantar App + DB + Dashboard.
- [ ] **6.3 MCP Server API:** Exponer las herramientas vía HTTP (SSE) para consumo de terceros (Claude Desktop, etc).

---

## 🛡️ Estándares de Seguridad

1.  **Safety First:** Ninguna herramienta se ejecuta sin pasar por `ScopeGuardian`.
2.  **Least Privilege:** El contenedor/proceso corre con usuario no-root.
3.  **Audit Trail:** Toda acción (exitosa o fallida) queda registrada en `ActionLogs`.

---

> **Nota:** Este roadmap es un documento vivo. Se actualizará conforme se completen los Sprints.