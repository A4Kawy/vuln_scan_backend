import os
import subprocess
import requests

def run_subfinder(domain):
    """
    Run Subfinder to enumerate subdomains for a given domain.
    """
    try:
        # Get the user's home directory
        home_dir = os.path.expanduser("~")
        # Path to subfinder in Go bin directory
        subfinder_path = os.path.join(home_dir, "go", "bin", "subfinder.exe")
        
        # Check if subfinder exists at the expected path
        if not os.path.exists(subfinder_path):
            return {
                "error": f"Subfinder not found at {subfinder_path}. Make sure it's installed correctly."
            }
            
        # Run Subfinder command and capture output
        result = subprocess.run(
            [subfinder_path, '-d', domain, '-silent'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if result.returncode != 0:
            return {
                "error": f"Subfinder failed with error: {result.stderr.decode()}"
            }

        # Decode and return the list of subdomains
        subdomains = result.stdout.decode().splitlines()
        return {
            "subdomains": subdomains
        }

    except Exception as e:
        return {
            "error": f"Unexpected error occurred: {e}"
        }

def check_status(subdomain):
    """
    Check the HTTP status code for a given subdomain.
    """
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def save_to_file(domain, valid_subdomains):
    """
    Save only subdomains with 200 OK status to a file.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Get script directory
    final_output_file = os.path.join(script_dir, f"{domain}_all_subdomains.txt")

    with open(final_output_file, 'w') as file:
        file.write("\n".join(valid_subdomains))

    return final_output_file

