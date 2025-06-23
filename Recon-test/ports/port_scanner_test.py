import os
import subprocess
import sys

def scan_target(ip, domain):
    """
    Scan a single target IP using the Nmap command-line tool and append output to a file.
    """
    open_ports = []
    output_filename = f"{domain}_ports.txt"

    try:
        # Run Nmap with optimized arguments
        print(f"[DEBUG] Running Nmap for {ip}: nmap -T4 --open -p 1-1000 {ip}", file=sys.stdout)
        result = subprocess.run(
            ["nmap", "-T4", "--open", "-p1-1000", "-O","-A", ip],
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout per IP
        )

        if result.returncode != 0:
            print(f"[-] Nmap scan failed for {ip}: {result.stderr}", file=sys.stderr)
            return {
                "error": f"Nmap scan failed for {ip} with error: {result.stderr}"
            }

        output = result.stdout

        # Parse results for open ports
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                service_name = parts[2] if len(parts) > 2 else "unknown"
                if service_name == "http-proxy":
                    service_name = "http" if port == "80" else "https"
                open_ports.append(f"{service_name}({port})")

        # Append output to the file (append mode to keep results from all IPs)
        with open(output_filename, "a") as file:
            file.write(f"\nScan results for IP: {ip}\n")
            file.write(output)

        print(f"[+] Nmap scan completed for {ip}. Appended to: {output_filename}", file=sys.stdout)
        return {
            "ip": ip,
            "open_ports": open_ports,
            "os_info": None,
            "output_file": output_filename
        }

    except subprocess.TimeoutExpired:
        print(f"[-] Nmap scan timed out for {ip}", file=sys.stderr)
        return {
            "error": f"Nmap scan timed out for {ip}"
        }
    except Exception as e:
        print(f"[-] Nmap error for {ip}: {str(e)}", file=sys.stderr)
        return {
            "error": f"An error occurred while scanning {ip}: {e}"
        }

def find_ip_files(target_name):
    """
    Find files named {target_name}_ips.txt in the current directory and subdirectories.
    """
    ip_files = []
    for root, _, files in os.walk("."):
        for file in files:
            if file.startswith(target_name) and file.endswith("_ips.txt"):
                ip_files.append(os.path.join(root, file))
    return ip_files