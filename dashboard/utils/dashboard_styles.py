/* ============================================
   BEREBRUM DASHBOARD - ESTILOS PRINCIPALES
   ============================================ */

/* ==========================================
   BADGES DE SEVERIDAD
   ========================================== */
.severity-badge {
    padding: 4px 12px;
    border-radius: 12px;
    font-weight: bold;
    font-size: 14px;
    display: inline-block;
    margin: 2px;
}

.critical { 
    background-color: #dc3545; 
    color: white; 
}

.high { 
    background-color: #fd7e14; 
    color: white; 
}

.medium { 
    background-color: #ffc107; 
    color: black; 
}

.low { 
    background-color: #28a745; 
    color: white; 
}

.none { 
    background-color: #6c757d; 
    color: white; 
}

/* ==========================================
   CARDS DE MÉTRICAS
   ========================================== */
.metric-card {
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    color: white;
    font-weight: bold;
}

.metric-critical { 
    background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); 
}

.metric-high { 
    background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); 
}

.metric-medium { 
    background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); 
    color: black; 
}

.metric-low { 
    background: linear-gradient(135deg, #28a745 0%, #218838 100%); 
}

.metric-neutral { 
    background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%); 
}

.metric-value {
    font-size: 36px;
    font-weight: bold;
    margin: 10px 0;
}

.metric-label {
    font-size: 14px;
    opacity: 0.9;
}

/* ==========================================
   BADGES DE CATEGORÍAS
   ========================================== */
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

/* ==========================================
   CARDS DE VULNERABILIDADES
   ========================================== */
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

.vuln-critical { 
    border-left-color: #dc3545; 
}

.vuln-high { 
    border-left-color: #fd7e14; 
}

.vuln-medium { 
    border-left-color: #ffc107; 
}

.vuln-low { 
    border-left-color: #28a745; 
}

/* ==========================================
   CARDS DE ATTACK FLOW
   ========================================== */
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

.attack-step-clean {
    background: rgba(40, 167, 69, 0.1);
    border-left-color: #28a745;
}

/* ==========================================
   PREVIEW CARDS
   ========================================== */
.preview-card {
    background: linear-gradient(135deg, rgba(26, 26, 46, 0.8) 0%, rgba(38, 38, 54, 0.6) 100%);
    padding: 15px;
    margin: 10px 0;
    border-radius: 8px;
    border-left: 4px solid;
}

.preview-card-critical {
    border-left-color: #dc3545;
}

.preview-card-success {
    border-left-color: #28a745;
}

.preview-card-warning {
    border-left-color: #fd7e14;
}

.preview-card-info {
    border-left-color: #17a2b8;
}

/* ==========================================
   UTILIDADES
   ========================================== */
.text-center {
    text-align: center;
}

.text-bold {
    font-weight: bold;
}

.text-muted {
    color: #6c757d;
}

.mb-3 {
    margin-bottom: 1rem;
}

.mt-3 {
    margin-top: 1rem;
}