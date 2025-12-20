"""
GENERAR DATOS DE PRUEBA - Attack Flow (VERSIÓN MÍNIMA)
Solo campos básicos que existen en Log
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

print("\n" + "="*70)
print("🔥 GENERANDO DATOS DE PRUEBA - SQL INJECTION CON ATTACK FLOW")
print("="*70 + "\n")

try:
    from core.database import db_manager
    from tools.exploit.sqli_scanner import scan_sqli
    import time
    import json
    
    print("✓ Módulos importados\n")
    
    # Inicializar BD
    db_manager.init_db()
    print("✓ Base de datos lista\n")
    
    # Crear proyecto
    timestamp = int(time.time())
    project_name = f"Attack_Flow_Demo_{timestamp}"
    
    print(f"📋 Creando proyecto: {project_name}...")
    project = db_manager.create_project(
        name=project_name,
        scope_ips="testphp.vulnweb.com",
        description="Demo de Attack Flow"
    )
    print(f"✓ Proyecto creado (ID: {project.id})\n")
    
    # Target
    target_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    print(f"🎯 Target: {target_url}")
    print(f"⏱️  Ejecutando scan...\n")
    
    # Ejecutar scan
    start = time.time()
    results = scan_sqli(target_url, scan_mode="normal")
    duration = time.time() - start
    
    print(f"✓ Scan completado en {duration:.1f}s\n")
    
    # Guardar en BD - SOLO campos básicos
    print("💾 Guardando en BD...")
    
    output_str = json.dumps(results)
    
    # create_log con MÍNIMOS argumentos
    log = db_manager.create_log(
        project_id=project.id,
        tool_name="SQL Injection Scanner",
        target=target_url,
        command=f"scan_sqli('{target_url}', 'normal')",
        output=output_str
    )
    
    print(f"✓ Log creado (ID: {log.id})\n")
    
    # Guardar vulnerabilidades
    if results.get("vulnerabilities"):
        print(f"💾 Guardando vulnerabilidades...")
        
        for vuln in results["vulnerabilities"]:
            cvss = 9.8 if vuln.get('severity') == 'Critical' else \
                   8.5 if vuln.get('severity') == 'High' else 6.5
            
            db_manager.create_vulnerability(
                project_id=project.id,
                title=f"SQL Injection - {vuln['technique'].upper()}",
                description=f"Parámetro '{vuln['parameter']}' vulnerable",
                target=target_url,
                cvss_score=cvss,
                severity=vuln.get('severity', 'High')
            )
        
        print(f"✓ {len(results['vulnerabilities'])} vulnerabilidades guardadas\n")
    
    # Exportar JSON
    flow_file = f"attack_flow_{timestamp}.json"
    with open(flow_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"✓ Attack Flow exportado: {flow_file}\n")
    
    # Resumen
    print("="*70)
    print("📊 RESUMEN")
    print("="*70 + "\n")
    
    print(f"Proyecto ID: {project.id}")
    print(f"Nombre: {project_name}")
    print(f"Log ID: {log.id}\n")
    
    print(f"Vulnerable: {'🚨 SÍ' if results.get('vulnerable') else '✅ NO'}")
    print(f"Confianza: {results.get('confidence', 0)}%")
    print(f"Base de datos: {results.get('database_type', 'Unknown')}\n")
    
    if results.get('attack_summary'):
        s = results['attack_summary']
        print(f"Attack Flow:")
        print(f"  Steps totales: {s['total_steps']}")
        print(f"  Steps vulnerables: {s['vulnerable_steps']}")
        print(f"  Técnicas: {', '.join(s['techniques_detected'])}\n")
    
    print("="*70)
    print("✅ DATOS GENERADOS EXITOSAMENTE")
    print("="*70 + "\n")
    
    print("PRÓXIMOS PASOS:\n")
    print("1. Actualizar dashboard:")
    print("   code dashboard/app.py")
    print("   Buscar: if tool_name == \"SQL Injection Scanner\":")
    print("   Pegar código de: 3_ATTACK_FLOW_DASHBOARD_VISUALIZATION.py\n")
    print("2. Ejecutar dashboard:")
    print(f"   streamlit run dashboard/app.py\n")
    print(f"3. Seleccionar proyecto: {project_name}\n")
    print("4. Ver Attack Flow en tab Resultados\n")
    print("="*70 + "\n")
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    print("\n" + traceback.format_exc())
    sys.exit(1)