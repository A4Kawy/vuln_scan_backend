import os
import sys
from subdomains_enum.subfinder_test import run_subfinder, save_to_file as save_subdomains
from ip_collector.ips_coll_test import extract_unique_ips, save_ips_to_file
from ports.port_scanner_test import find_ip_files, scan_target
from crawler.crawl_test import find_subdomain_file, run_katana

# Import vulnerability scanners
try:
    from xss_scanner.xss_test import scan_xss
except ImportError:
    print("[!] Warning: XSS scanner module not found or has errors.")
    def scan_xss(params_file): return []

try:
    from lfi_scanner.lfi_test import scan_lfi
except ImportError:
    print("[!] Warning: LFI scanner module not found or has errors.")
    def scan_lfi(params_file): return []

try:
    from cmdi_scanner.cmdi_test import scan_cmdi
except ImportError:
    print("[!] Warning: Command Injection scanner module not found or has errors.")
    def scan_cmdi(params_file): return []

try:
    from sqli_scanner.sqli_test import scan_sqli
except ImportError:
    print("[!] Warning: SQL Injection scanner module not found or has errors.")
    def scan_sqli(params_file): return []

try:
    from csrf_scanner.csrf_test import scan_csrf
except ImportError:
    print("[!] Warning: CSRF scanner module not found or has errors.")
    def scan_csrf(params_file): return []

try:
    from sensitive_data_scanner.sensitive_data_test import scan_sensitive_data
except ImportError:
    print("[!] Warning: Sensitive Data scanner module not found or has errors.")
    def scan_sensitive_data(params_file): return []

try:
    from ssti_scanner.ssti_test import scan_ssti
except ImportError:
    print("[!] Warning: SSTI scanner module not found or has errors.")
    def scan_ssti(params_file): return []

try:
    from xxe_scanner.xxe_test import scan_xxe
except ImportError:
    print("[!] Warning: XXE scanner module not found or has errors.")
    def scan_xxe(params_file): return []

# Define empty function for Insecure Deserialization to avoid errors
def scan_deserialization(params_file): return []

try:
    from http_smuggling_scanner.http_smuggling_test import scan_http_smuggling
except ImportError:
    print("[!] Warning: HTTP Request Smuggling scanner module not found or has errors.")
    def scan_http_smuggling(params_file): return []

def parse_ports_file(ports_file):
    """
    Parse the ports file to extract open ports and their corresponding versions.
    """
    open_ports = {}
    try:
        with open(ports_file, "r") as file:
            for line in file:
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port = parts[0].split("/")[0]
                    version = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                    open_ports[port] = version
    except FileNotFoundError:
        print(f"[!] Ports file {ports_file} not found.")
    return open_ports

def run_vulnerability_scans(domain, params_file_path):
    """
    Run vulnerability scans on the parameters file.
    
    Args:
        domain: The target domain
        params_file_path: Path to the file containing URLs with parameters
    
    Returns:
        Dictionary containing vulnerability scan results
    """
    results = {
        "xss": [],
        "lfi": [],
        "cmdi": [],
        "sqli": [],
        "csrf": [],
        "sensitive_data": [],
        "ssti": [],
        "xxe": [],
        "deserialization": [],
        "http_smuggling": []
    }
    
    if not os.path.exists(params_file_path):
        print(f"[!] Parameters file not found: {params_file_path}")
        return results
    
    # Check parameters file content
    try:
        with open(params_file_path, 'r') as f:
            params_content = f.read().strip()
            params_lines = params_content.split('\n')
            print(f"[+] Parameters file contains {len(params_lines)} URLs")
            if len(params_lines) == 0:
                print("[!] Parameters file is empty. Skipping vulnerability scanning.")
                return results
            print(f"[+] First URL in parameters file: {params_lines[0]}")
    except Exception as e:
        print(f"[!] Error reading parameters file: {str(e)}")
    
    # Copy parameters file to results directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results_all")
    domain_results_dir = os.path.join(results_dir, domain)
    
    try:
        os.makedirs(domain_results_dir, exist_ok=True)
        with open(params_file_path, 'r') as src, open(os.path.join(domain_results_dir, f"{domain}_params.txt"), 'w') as dst:
            dst.write(src.read())
        print(f"[+] Parameters file copied to: {os.path.join(domain_results_dir, f'{domain}_params.txt')}")
    except Exception as e:
        print(f"[!] Error copying parameters file: {str(e)}")
    
    # Run all scanners
    scanners = [
        ("XSS", scan_xss, "xss"),
        ("LFI", scan_lfi, "lfi"),
        ("Command Injection", scan_cmdi, "cmdi"),
        ("SQL Injection", scan_sqli, "sqli"),
        ("CSRF", scan_csrf, "csrf"),
        ("Sensitive Data", scan_sensitive_data, "sensitive_data"),
        ("SSTI", scan_ssti, "ssti"),
        ("XXE", scan_xxe, "xxe"),
        ("Insecure Deserialization", scan_deserialization, "deserialization"),
        ("HTTP Request Smuggling", scan_http_smuggling, "http_smuggling")
    ]
    
    for scanner_name, scanner_func, result_key in scanners:
        print(f"\n[+] Starting {scanner_name} Vulnerability Scanning...")
        try:
            print(f"[+] Calling {scanner_func.__name__} with file: {params_file_path}")
            scanner_results = scanner_func(params_file_path)
            print(f"[+] {scanner_name} scan returned: {type(scanner_results)}")
            
            if isinstance(scanner_results, list):
                results[result_key] = scanner_results
                print(f"[+] {scanner_name} results (list): {len(scanner_results)} items")
            elif isinstance(scanner_results, dict) and "results" in scanner_results:
                results[result_key] = scanner_results["results"]
                print(f"[+] {scanner_name} results (dict): {len(scanner_results['results'])} items")
            else:
                print(f"[!] Unexpected {scanner_name} results format: {scanner_results}")
                results[result_key] = []
            print(f"[+] {scanner_name} Scanning completed. Found {len(results[result_key])} potential vulnerabilities.")
        except Exception as e:
            print(f"[!] Error during {scanner_name} scanning: {str(e)}")
            import traceback
            traceback.print_exc()
    
    return results

def display_vulnerability_summary(vuln_results, domain):
    """
    Display a summary of vulnerability scan results.
    
    Args:
        vuln_results: Dictionary containing vulnerability scan results
        domain: The target domain
    """
    print(f"\n[+] Vulnerability Scan Summary for {domain}:")
    
    # Define all vulnerability types
    vuln_types = {
        "xss": "XSS",
        "lfi": "LFI",
        "cmdi": "Command Injection",
        "sqli": "SQL Injection",
        "csrf": "CSRF",
        "sensitive_data": "Sensitive Data",
        "ssti": "SSTI",
        "xxe": "XXE",
        "deserialization": "Insecure Deserialization",
        "http_smuggling": "HTTP Request Smuggling"
    }
    
    total_vulns = 0
    
    # Display results for each vulnerability type
    for vuln_key, vuln_name in vuln_types.items():
        vuln_count = len(vuln_results.get(vuln_key, []))
        total_vulns += vuln_count
        print(f"    - {vuln_name} Vulnerabilities: {vuln_count}")
        
        if vuln_count > 0:
            print(f"      Top {min(3, vuln_count)} vulnerable endpoints:")
            for i, result in enumerate(vuln_results.get(vuln_key, [])[:3]):
                url = result.get('url', 'Unknown URL')
                param = result.get('param', 'Unknown')
                print(f"        * {url} - Parameter: {param}")
    
    # Total vulnerabilities
    print(f"\n    Total Vulnerabilities Found: {total_vulns}")
    
    # Create results directory structure
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results_all")
    domain_results_dir = os.path.join(results_dir, domain)
    
    # Create directories if they don't exist
    os.makedirs(domain_results_dir, exist_ok=True)
    
    print(f"\n[+] Detailed results can be found in: {domain_results_dir}")
    
    # Copy result files to the new structure
    for vuln_key, vuln_name in vuln_types.items():
        # Check multiple possible locations for result files
        possible_source_files = [
            os.path.join(script_dir, f"{vuln_key}_scanner", f"{domain}_{vuln_key}_results.txt"),
            os.path.join(script_dir, "crawler", f"{domain}_{vuln_key}_results.txt"),
            os.path.join(script_dir, f"{domain}_{vuln_key}_results.txt")
        ]
        
        target_file = os.path.join(domain_results_dir, f"{domain}_{vuln_key}_results.txt")
        file_copied = False
        
        for source_file in possible_source_files:
            if os.path.exists(source_file):
                try:
                    # Copy the file content
                    with open(source_file, 'r') as src, open(target_file, 'w') as dst:
                        dst.write(src.read())
                    print(f"    - {vuln_name}: {target_file}")
                    file_copied = True
                    break
                except Exception as e:
                    print(f"    - {vuln_name}: Error copying results - {str(e)}")
        
        if not file_copied:
            # Create an empty file if source doesn't exist
            with open(target_file, 'w') as f:
                f.write(f"No {vuln_name} vulnerabilities found for {domain}\n")
            print(f"    - {vuln_name}: {target_file} (No vulnerabilities found)")

def main(domain=None):
    """
    Main function to orchestrate the scanning process for a given domain or subdomain.
    """
    print(f"[DEBUG] Script started with domain: {domain}", file=sys.stdout)
    if len(sys.argv) > 1:
        domain = sys.argv[1].strip()
        print(f"[DEBUG] Domain from sys.argv: {domain}", file=sys.stdout)
    if not domain:
        print("[!] Domain name is required. Exiting.", file=sys.stderr)
        sys.exit(1)

    # Create results directory structure at the beginning
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, "results_all")
    domain_results_dir = os.path.join(results_dir, domain)
    
    # Create directories if they don't exist
    os.makedirs(domain_results_dir, exist_ok=True)
    print(f"[+] Results will be saved to: {domain_results_dir}")

    # Step 1: Determine if input is a domain or subdomain
    print("\n[+] Analyzing input...")
    # Use dot count to identify domain (e.g., example.com) vs subdomain (e.g., sub.example.com)
    is_subdomain = domain.count('.') > 1  # Subdomains typically have more than one dot
    print(f"[+] Input identified as {'subdomain' if is_subdomain else 'domain'}: {domain}")

    # Step 2: Subdomain Enumeration
    print("\n[+] Starting Subdomain Enumeration...")
    if is_subdomain:
        # Skip enumeration for subdomains; use input directly
        subdomains = [domain]
        subfinder_results = {"subdomains": subdomains}
        print(f"[+] Using provided subdomain: {domain}")
    else:
        # Perform enumeration for domains
        subfinder_results = run_subfinder(domain)
        subdomains = subfinder_results.get("subdomains", [])
        if not subdomains:
            print(f"[!] No subdomains found for {domain}. Using root domain instead.")
            subdomains = [domain]

    # Save subdomains to file
    subdomains_file = save_subdomains(domain, subdomains)
    print(f"[+] Subdomains saved to: {subdomains_file}")
    
    # Copy subdomains file to results directory
    target_subdomains_file = os.path.join(domain_results_dir, f"{domain}_all_subdomains.txt")
    try:
        with open(subdomains_file, 'r') as src, open(target_subdomains_file, 'w') as dst:
            dst.write(src.read())
        print(f"[+] Subdomains also saved to: {target_subdomains_file}")
    except Exception as e:
        print(f"[!] Error copying subdomains file: {str(e)}")

    # Step 3: IP Collection
    print("\n[+] Starting IP Collection...")
    unique_ips = extract_unique_ips(subdomains)
    if not unique_ips:
        print("[!] No unique IPs found. Continuing to next step...")
        ips_file = None
    else:
        ips_file = save_ips_to_file(unique_ips, domain)
        print(f"[+] IPs saved to: {ips_file}")
        
        # Copy IPs file to results directory
        target_ips_file = os.path.join(domain_results_dir, f"{domain}_ips.txt")
        try:
            with open(ips_file, 'r') as src, open(target_ips_file, 'w') as dst:
                dst.write(src.read())
            print(f"[+] IPs also saved to: {target_ips_file}")
        except Exception as e:
            print(f"[!] Error copying IPs file: {str(e)}")

    # Step 4: Port Scanning
    print("\n[+] Starting Port Scanning...")
    ip_files = find_ip_files(domain) if unique_ips else []
    if not ip_files:
        print("[!] No IP files found for port scanning. Continuing to next step...")
    else:
        for ip_file in ip_files:
            print(f"[+] Scanning IPs from file: {ip_file}")
            with open(ip_file, "r") as file:
                ips = [ip.strip() for ip in file if ip.strip()]

            for ip in ips:
                result = scan_target(ip, domain)
                if "error" in result:
                    print(f"[!] Error scanning {ip}: {result['error']}")
        
        # Copy ports file to results directory if it exists
        ports_file = os.path.join(script_dir, f"{domain}_ports.txt")
        target_ports_file = os.path.join(domain_results_dir, f"{domain}_ports.txt")
        if os.path.exists(ports_file):
            try:
                with open(ports_file, 'r') as src, open(target_ports_file, 'w') as dst:
                    dst.write(src.read())
                print(f"[+] Port scan results also saved to: {target_ports_file}")
            except Exception as e:
                print(f"[!] Error copying ports file: {str(e)}")

    # Step 5: Crawling
    print("\n[+] Starting Crawling...")
    subdomains_file_path = find_subdomain_file(domain)
    if not subdomains_file_path:
        print(f"[!] Subdomains file for crawling not found. Exiting.")
        return

    crawler_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crawler")
    crawl_result = run_katana(subdomains_file_path, crawler_dir, domain)
    
    if isinstance(crawl_result, dict):
        print(f"[+] Crawling completed. Found {crawl_result.get('total_urls', 0)} URLs.")
        print(f"[+] URLs with parameters: {crawl_result.get('urls_with_params', 0)}")
        print(f"[+] URLs without parameters: {crawl_result.get('urls_without_params', 0)}")
        
        # Copy all crawler files to results directory
        crawler_files_to_copy = [
            f"{domain}_params.txt",
            f"{domain}_others.txt",
            f"{domain}_all_urls.txt",
        ]
        
        for file_name in crawler_files_to_copy:
            source_file = os.path.join(crawler_dir, file_name)
            if os.path.exists(source_file):
                target_file = os.path.join(domain_results_dir, file_name)
                try:
                    with open(source_file, 'r') as src, open(target_file, 'w') as dst:
                        dst.write(src.read())
                    print(f"[+] Crawler file copied to: {target_file}")
                except Exception as e:
                    print(f"[!] Error copying crawler file {file_name}: {str(e)}")
        
        # Copy all vulnerability result files from crawler directory
        vuln_result_files = [f for f in os.listdir(crawler_dir) if f.endswith('_results.txt')]
        for file_name in vuln_result_files:
            source_file = os.path.join(crawler_dir, file_name)
            target_file = os.path.join(domain_results_dir, file_name)
            try:
                with open(source_file, 'r') as src, open(target_file, 'w') as dst:
                    dst.write(src.read())
                print(f"[+] Vulnerability result file copied to: {target_file}")
            except Exception as e:
                print(f"[!] Error copying vulnerability result file {file_name}: {str(e)}")
        
        # Copy parameters file to results directory
        params_file_path = os.path.join(crawler_dir, f"{domain}_params.txt")
        if os.path.exists(params_file_path):
            target_params_file = os.path.join(domain_results_dir, f"{domain}_params.txt")
            try:
                with open(params_file_path, 'r') as src, open(target_params_file, 'w') as dst:
                    dst.write(src.read())
                print(f"[+] Parameters file copied to: {target_params_file}")
            except Exception as e:
                print(f"[!] Error copying parameters file: {str(e)}")
        
        # Step 6: Vulnerability Scanning
        print("\n[+] Starting Vulnerability Scanning...")
        if os.path.exists(params_file_path):
            print(f"[+] Found parameters file: {params_file_path}")
            print(f"[+] Parameters file size: {os.path.getsize(params_file_path)} bytes")
            
            if os.path.getsize(params_file_path) > 0:
                vuln_results = run_vulnerability_scans(domain, params_file_path)
                display_vulnerability_summary(vuln_results, domain)
            else:
                print(f"[!] Parameters file is empty. Skipping vulnerability scanning.")
        else:
            print(f"[!] Parameters file not found: {params_file_path}. Skipping vulnerability scanning.")
    else:
        print(f"[!] Crawling error: {crawl_result}")

    # Step 7: Summary
    print("\n[+] Generating Reconnaissance Summary...")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    num_subdomains = 0
    if os.path.exists(subdomains_file):
        with open(subdomains_file, "r") as file:
            num_subdomains = len(file.readlines())

    num_unique_ips = 0
    if ips_file and os.path.exists(ips_file):
        with open(ips_file, "r") as file:
            num_unique_ips = len(file.readlines())

    ports_file = os.path.join(script_dir, f"{domain}_ports.txt")
    open_ports = parse_ports_file(ports_file)
    
    if os.path.exists(ports_file):
        target_ports_file = os.path.join(domain_results_dir, f"{domain}_ports.txt")
        try:
            with open(ports_file, 'r') as src, open(target_ports_file, 'w') as dst:
                dst.write(src.read())
            print(f"[+] Ports file copied to: {target_ports_file}")
        except Exception as e:
            print(f"[!] Error copying ports file: {str(e)}")
    else:
        target_ports_file = os.path.join(domain_results_dir, f"{domain}_ports.txt")
        with open(target_ports_file, 'w') as f:
            f.write(f"No open ports found for {domain}\n")
        print(f"[+] Empty ports file created at: {target_ports_file}")

    print(f"\n[+] Reconnaissance Summary for domain {domain}:")
    print(f"    - Subdomains found: {num_subdomains}")
    print(f"    - Unique IPs found: {num_unique_ips}")
    if open_ports:
        print(f"    - Open Ports:")
        for port, version in open_ports.items():
            print(f"        * Port {port}: {version}")
    else:
        print(f"    - No open ports detected.")

if __name__ == "__main__":
    main()