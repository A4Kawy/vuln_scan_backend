import socket
import os

def resolve_subdomain_to_ip(subdomain):
    """
    Resolve a subdomain to its IP address.
    """
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None

def extract_unique_ips(subdomains):
    """
    Extract unique IPs for a list of subdomains.
    """
    unique_ips = set()
    for subdomain in subdomains:
        ip = resolve_subdomain_to_ip(subdomain)
        if ip:
            unique_ips.add(ip)
    return unique_ips

def save_ips_to_file(unique_ips, domain):
    """
    Save unique IPs to a file.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_name = os.path.join(script_dir, f"{domain}_ips.txt")
    with open(file_name, 'w') as f:
        for ip in unique_ips:
            f.write(f"{ip}\n")
    return file_name

def search_for_file(target):
    """
    Search for a file in the entire project folder that matches the pattern {target}_all_subdomains.txt
    """
    target_file_name = f"{target}_all_subdomains.txt"
    
    for root, dirs, files in os.walk(os.getcwd()):
        if target_file_name in files:
            file_path = os.path.join(root, target_file_name)
            return file_path
    return None
