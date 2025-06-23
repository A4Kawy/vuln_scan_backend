import os
import requests
import urllib.parse
import json
import time
import random
import string
import re
import base64
import pickle
import yaml
from concurrent.futures import ThreadPoolExecutor

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

# Common serialization formats and their identifiers
SERIALIZATION_FORMATS = {
    'php': {
        'identifiers': ['O:', 's:', 'a:', 'i:', 'd:', 'b:'],
        'cookies': ['PHPSESSID', 'PHP_SESSION_ID'],
        'extensions': ['.php'],
        'content_types': ['application/x-www-form-urlencoded', 'application/php'],
        'description': 'PHP serialization format'
    },
    'java': {
        'identifiers': ['rO0', 'AC2', 'H4s', 'aced0005'],
        'cookies': ['JSESSIONID', 'JSESSION'],
        'extensions': ['.jsp', '.do', '.action'],
        'content_types': ['application/x-java-serialized-object'],
        'description': 'Java serialization format'
    },
    'python': {
        'identifiers': ['gASV', 'KGlwMQ', 'cposix', 'cbuiltins', 'c__builtin', 'cPickle'],
        'cookies': ['PYTHONSESSION', 'FLASK_SESSION', 'session'],
        'extensions': ['.py', '.pyc', '.pyo'],
        'content_types': ['application/python-pickle', 'application/octet-stream'],
        'description': 'Python pickle serialization format'
    },
    'ruby': {
        'identifiers': ['BAh', 'BAhT', 'BAhU', 'BAhb'],
        'cookies': ['_session_id', 'rack.session'],
        'extensions': ['.rb', '.rhtml', '.erb'],
        'content_types': ['application/x-ruby-marshal'],
        'description': 'Ruby Marshal serialization format'
    },
    'node': {
        'identifiers': ['j:', 'eyJ'],
        'cookies': ['connect.sid', 'express:sess'],
        'extensions': ['.js', '.node'],
        'content_types': ['application/json'],
        'description': 'Node.js serialization format (often JSON)'
    },
    'dotnet': {
        'identifiers': ['AAEAAAD', 'AQQAAA', '/wEA'],
        'cookies': ['.ASPXAUTH', 'ASP.NET_SessionId'],
        'extensions': ['.aspx', '.ashx', '.asmx'],
        'content_types': ['application/x-www-form-urlencoded'],
        'description': '.NET serialization format'
    }
}

# Payloads for testing insecure deserialization
# These are harmless payloads that might trigger errors revealing deserialization issues
DESERIALIZATION_PAYLOADS = {
    'php': [
        'O:8:"stdClass":0:{}',
        'a:1:{s:4:"test";s:4:"test";}',
        'O:1:"A":1:{s:1:"a";s:1:"a";}',
        'O:8:"NonExistingClass":0:{}',
        'O:11:"SimpleXMLElement":1:{s:4:"data";s:14:"<tag>data</tag>";}',
    ],
    'java': [
        base64.b64encode(b'\xac\xed\x00\x05sr\x00\x0ejava.lang.Void\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78p').decode(),
        base64.b64encode(b'\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01').decode(),
        base64.b64encode(b'\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02F\x00\x0aloadFactorI\x00\x09thresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01t\x00\x04testt\x00\x04testx').decode(),
    ],
    'python': [
        base64.b64encode(pickle.dumps({'test': 'test'})).decode(),
        base64.b64encode(pickle.dumps(['test', 1, 2])).decode(),
        base64.b64encode(pickle.dumps(('test', 'data'))).decode(),
    ],
    'ruby': [
        'BAh7BzoIdGVzdCIIdGVzdA==',  # Marshal.dump({test: 'test'})
        'BAhbBiIIdGVzdGkGaQc=',      # Marshal.dump(['test', 1, 2])
    ],
    'node': [
        'j:{"test":"test"}',
        'j:[1,2,3]',
        'eyJ0ZXN0IjoidGVzdCJ9',  # Base64 of {"test":"test"}
    ],
    'dotnet': [
        '/wEWAgLigKDCBwKl1w6zCA==',
        '/wEWAwKigKDCBwLigaDCBwLigaLCBw==',
    ]
}

# Error patterns that might indicate insecure deserialization
ERROR_PATTERNS = {
    'php': [
        'unserialize\(\):',
        'Error at offset',
        'cannot be unserialized',
        'Uncaught Exception',
        'Uncaught TypeError',
        'Class .* not found',
        '__PHP_Incomplete_Class',
    ],
    'java': [
        'java.io.InvalidClassException',
        'java.lang.ClassNotFoundException',
        'java.io.StreamCorruptedException',
        'java.io.InvalidObjectException',
        'java.io.OptionalDataException',
        'java.lang.reflect.InvocationTargetException',
        'ClassCastException',
        'java.io.EOFException',
    ],
    'python': [
        'pickle.UnpicklingError',
        'AttributeError: .* has no attribute',
        'ImportError: No module named',
        'ModuleNotFoundError',
        'EOFError',
        'ValueError: unsupported pickle protocol',
        'TypeError: __new__\(\) missing',
    ],
    'ruby': [
        'undefined class/module',
        'ArgumentError',
        'TypeError',
        'Marshal.load',
        'incompatible marshal file format',
    ],
    'node': [
        'SyntaxError: Unexpected token',
        'SyntaxError: Unexpected end of JSON input',
        'Error: Cannot find module',
    ],
    'dotnet': [
        'System.Runtime.Serialization.SerializationException',
        'System.InvalidCastException',
        'System.IO.InvalidDataException',
        'System.ArgumentException',
        'System.FormatException',
        'Unable to find assembly',
    ]
}

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

def detect_serialization_format(data):
    """
    Detect potential serialization format from data.
    Returns a list of potential formats.
    """
    potential_formats = []
    
    # Convert to string if it's bytes
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8')
        except:
            try:
                data = data.decode('latin-1')
            except:
                # If we can't decode, try base64
                try:
                    data = base64.b64encode(data).decode('utf-8')
                except:
                    return potential_formats
    
    # Check for each format's identifiers
    for format_name, format_info in SERIALIZATION_FORMATS.items():
        for identifier in format_info['identifiers']:
            if identifier in data:
                potential_formats.append(format_name)
                break
    
    return potential_formats

def check_cookies_for_serialization(cookies):
    """
    Check if any cookies might contain serialized data.
    Returns a list of (cookie_name, format) tuples.
    """
    serialized_cookies = []
    
    for cookie_name, cookie_value in cookies.items():
        # First check if the cookie name matches known session cookie names
        matched_formats = []
        for format_name, format_info in SERIALIZATION_FORMATS.items():
            if any(session_cookie.lower() in cookie_name.lower() for session_cookie in format_info['cookies']):
                matched_formats.append(format_name)
        
        # Then check the cookie value for serialization format identifiers
        detected_formats = detect_serialization_format(cookie_value)
        
        # Combine the results, prioritizing format detection from the value
        formats = detected_formats + [f for f in matched_formats if f not in detected_formats]
        
        if formats:
            serialized_cookies.append((cookie_name, formats))
    
    return serialized_cookies

def check_response_for_errors(response_text, format_name):
    """
    Check if the response contains error messages that might indicate deserialization issues.
    """
    if format_name not in ERROR_PATTERNS:
        return False, None
    
    for pattern in ERROR_PATTERNS[format_name]:
        match = re.search(pattern, response_text)
        if match:
            return True, match.group(0)
    
    return False, None

def analyze_with_gemini(url, format_name, cookie_name=None, param_name=None, error=None, response_content=None):
    """
    Use Gemini API to analyze if the response indicates insecure deserialization.
    """
    prompt = f"""
    I need to analyze if this web application might be vulnerable to insecure deserialization.
    
    URL: {url}
    Detected Format: {format_name} ({SERIALIZATION_FORMATS[format_name]['description']})
    {"Cookie Name: " + cookie_name if cookie_name else ""}
    {"Parameter Name: " + param_name if param_name else ""}
    {"Error Message: " + error if error else ""}
    
    Response (truncated if necessary):
    {response_content[:4000] if response_content else "No response content provided"}
    
    Please analyze if:
    1. The error message indicates insecure deserialization
    2. The application appears to be deserializing user-controlled input
    3. There are any signs of deserialization-related vulnerabilities
    4. The format detected is likely to be a serialized object
    
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

def test_url_for_deserialization(url):
    """Test a URL for insecure deserialization vulnerabilities."""
    print(f"Testing URL: {url}")
    results = []
    
    try:
        # Make an initial request to get cookies and check response
        session = requests.Session()
        response = session.get(url, headers=HEADERS, timeout=10)
        
        # Check if the URL is accessible
        if response.status_code != 200:
            print(f"URL {url} returned status code {response.status_code}")
            return results
        
        # Parse the URL to get parameters
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check cookies for serialized data
        serialized_cookies = check_cookies_for_serialization(session.cookies.get_dict())
        
        if serialized_cookies:
            print(f"Found {len(serialized_cookies)} cookies that might contain serialized data")
            
            # Test each cookie with payloads
            for cookie_name, formats in serialized_cookies:
                original_value = session.cookies.get(cookie_name)
                
                for format_name in formats:
                    print(f"Testing cookie {cookie_name} for {format_name} deserialization")
                    
                    if format_name not in DESERIALIZATION_PAYLOADS:
                        continue
                    
                    for payload in DESERIALIZATION_PAYLOADS[format_name]:
                        # Create a new session with the modified cookie
                        test_session = requests.Session()
                        test_session.headers.update(HEADERS)
                        
                        # Set the cookie with the payload
                        test_session.cookies.set(cookie_name, payload)
                        
                        try:
                            test_response = test_session.get(url, timeout=10)
                            
                            # Check for error messages
                            has_error, error_message = check_response_for_errors(test_response.text, format_name)
                            
                            if has_error:
                                print(f"Potential deserialization vulnerability found in cookie {cookie_name} with format {format_name}")
                                
                                # Use Gemini for more advanced analysis
                                is_vulnerable, explanation = analyze_with_gemini(
                                    url, format_name, cookie_name=cookie_name, 
                                    error=error_message, response_content=test_response.text
                                )
                                
                                if is_vulnerable:
                                    results.append({
                                        'url': url,
                                        'type': 'cookie',
                                        'name': cookie_name,
                                        'format': format_name,
                                        'payload': payload,
                                        'error': error_message,
                                        'status': 'Potential Insecure Deserialization Vulnerability',
                                        'analysis': explanation
                                    })
                                    break
                        except Exception as e:
                            print(f"Error testing cookie {cookie_name} with payload: {e}")
        
        # Check query parameters for serialized data
        for param_name, param_values in query_params.items():
            param_value = param_values[0]
            detected_formats = detect_serialization_format(param_value)
            
            if detected_formats:
                print(f"Parameter {param_name} might contain serialized data in formats: {', '.join(detected_formats)}")
                
                for format_name in detected_formats:
                    print(f"Testing parameter {param_name} for {format_name} deserialization")
                    
                    if format_name not in DESERIALIZATION_PAYLOADS:
                        continue
                    
                    for payload in DESERIALIZATION_PAYLOADS[format_name]:
                        # Create a test URL with the payload
                        test_params = {p: v[0] for p, v in query_params.items()}
                        test_params[param_name] = payload
                        test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                        
                        try:
                            test_response = session.get(test_url, timeout=10)
                            
                            # Check for error messages
                            has_error, error_message = check_response_for_errors(test_response.text, format_name)
                            
                            if has_error:
                                print(f"Potential deserialization vulnerability found in parameter {param_name} with format {format_name}")
                                
                                # Use Gemini for more advanced analysis
                                is_vulnerable, explanation = analyze_with_gemini(
                                    url, format_name, param_name=param_name, 
                                    error=error_message, response_content=test_response.text
                                )
                                
                                if is_vulnerable:
                                    results.append({
                                        'url': url,
                                        'type': 'parameter',
                                        'name': param_name,
                                        'format': format_name,
                                        'payload': payload,
                                        'error': error_message,
                                        'status': 'Potential Insecure Deserialization Vulnerability',
                                        'analysis': explanation
                                    })
                                    break
                        except Exception as e:
                            print(f"Error testing parameter {param_name} with payload: {e}")
        
        # Check for POST parameters if there's a form
        if '<form' in response.text.lower():
            print("Found form, checking for POST parameters")
            
            # Simple form extraction
            form_action = re.search(r'<form.*?action=["\'](.*?)["\']', response.text, re.IGNORECASE)
            form_method = re.search(r'<form.*?method=["\'](.*?)["\']', response.text, re.IGNORECASE)
            
            action_url = form_action.group(1) if form_action else url
            method = form_method.group(1).lower() if form_method else 'get'
            
            # Make action URL absolute if it's relative
            if action_url and not action_url.startswith(('http://', 'https://')):
                action_url = urllib.parse.urljoin(url, action_url)
            
            # Extract input fields
            input_fields = re.findall(r'<input.*?name=["\'](.*?)["\']', response.text, re.IGNORECASE)
            
            if input_fields and method == 'post':
                print(f"Found {len(input_fields)} input fields in a POST form")
                
                # Test each input field with serialized data
                for field_name in input_fields:
                    for format_name, payloads in DESERIALIZATION_PAYLOADS.items():
                        for payload in payloads:
                            # Create form data with the payload
                            form_data = {field: 'test' for field in input_fields}
                            form_data[field_name] = payload
                            
                            try:
                                post_response = session.post(action_url, data=form_data, timeout=10)
                                
                                # Check for error messages
                                has_error, error_message = check_response_for_errors(post_response.text, format_name)
                                
                                if has_error:
                                    print(f"Potential deserialization vulnerability found in POST parameter {field_name} with format {format_name}")
                                    
                                    # Use Gemini for more advanced analysis
                                    is_vulnerable, explanation = analyze_with_gemini(
                                        action_url, format_name, param_name=field_name, 
                                        error=error_message, response_content=post_response.text
                                    )
                                    
                                    if is_vulnerable:
                                        results.append({
                                            'url': action_url,
                                            'type': 'post_parameter',
                                            'name': field_name,
                                            'format': format_name,
                                            'payload': payload,
                                            'error': error_message,
                                            'status': 'Potential Insecure Deserialization Vulnerability',
                                            'analysis': explanation
                                        })
                                        break
                            except Exception as e:
                                print(f"Error testing POST parameter {field_name} with payload: {e}")
    
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def scan_deserialization(urls_file_path, max_workers=3):
    """
    Scan URLs for insecure deserialization vulnerabilities.
    
    Args:
        urls_file_path: Path to the file containing URLs
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential insecure deserialization vulnerabilities
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
            results = list(executor.map(test_url_for_deserialization, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(urls_file_path)
    domain = os.path.basename(urls_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_deserialization_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("Insecure Deserialization Vulnerability Scan Results\n")
            f.write("===============================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Type: {result['type']}\n")
                f.write(f"Name: {result['name']}\n")
                f.write(f"Format: {result['format']}\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Error: {result['error']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No insecure deserialization vulnerabilities found.\n")
    
    return all_results

def test_specific_url(target_url):
    """Test a specific URL for insecure deserialization vulnerabilities."""
    print(f"Testing URL: {target_url}")
    
    results = test_url_for_deserialization(target_url)
    
    if results:
        print(f"\nFound {len(results)} potential insecure deserialization vulnerabilities!")
        for result in results:
            print(f"\nURL: {result['url']}")
            print(f"Type: {result['type']}")
            print(f"Name: {result['name']}")
            print(f"Format: {result['format']}")
            print(f"Payload: {result['payload']}")
            print(f"Error: {result['error']}")
            print(f"Status: {result['status']}")
            print(f"Analysis: {result['analysis']}")
    else:
        print("\nNo insecure deserialization vulnerabilities found.")
    
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
            results = scan_deserialization(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential insecure deserialization vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Type: {result['type']}")
                    print(f"Name: {result['name']}")
                    print(f"Format: {result['format']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Error: {result['error']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo insecure deserialization vulnerabilities found.")
    else:
        print("Usage: python deserialization_test.py <path_to_urls_file_or_direct_url>")
        print("Examples:")
        print("  python deserialization_test.py C:\\Users\\begad\\OneDrive\\Desktop\\New folder (3)\\Recon-test\\crawler\\example.com_urls.txt")
        print("  python deserialization_test.py https://example.com")