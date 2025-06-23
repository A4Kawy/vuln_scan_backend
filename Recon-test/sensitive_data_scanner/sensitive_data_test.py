import os
import requests
import urllib.parse
import json
import time
import random
import string
import re
import base64
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

# Gemini API configuration
GEMINI_API_KEY = "AIzaSyBRD2TjLNSV5LnTfD38DIy5CWjQy4SGJ_M"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

# Patterns for sensitive data detection
SENSITIVE_DATA_PATTERNS = {
    # API Keys and Tokens
    "API Keys": [
        r"api[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"api[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"access[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"auth[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"client[_-]?secret[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"secret[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"bearer[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
        r"authorization:\s*bearer\s+([a-zA-Z0-9\._\-]+)",
        r"jwt[^a-zA-Z0-9]([a-zA-Z0-9]{16,64})",
    ],
    
    # AWS Keys
    "AWS Keys": [
        r"AKIA[0-9A-Z]{16}",
        r"aws_access_key_id[^a-zA-Z0-9]([a-zA-Z0-9]{16,32})",
        r"aws_secret_access_key[^a-zA-Z0-9]([a-zA-Z0-9\/+]{40})",
    ],
    
    # Google API Keys
    "Google API Keys": [
        r"AIza[0-9A-Za-z\-_]{35}",
        r"ya29\.[0-9A-Za-z\-_]+",
    ],
    
    # Firebase Keys
    "Firebase": [
        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    ],
    
    # Private Keys and Certificates
    "Private Keys": [
        r"-----BEGIN\s+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
        r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
    ],
    
    # Certificates
    "Certificates": [
        r"-----BEGIN\s+CERTIFICATE-----",
        r"-----BEGIN\s+X509\s+CERTIFICATE-----",
        r"-----BEGIN\s+CERTIFICATE\s+REQUEST-----",
    ],
    
    # Database Connection Strings
    "Database Strings": [
        r"jdbc:mysql://[a-zA-Z0-9\.\-_:]+/[a-zA-Z0-9\.\-_]+",
        r"jdbc:postgresql://[a-zA-Z0-9\.\-_:]+/[a-zA-Z0-9\.\-_]+",
        r"jdbc:oracle:thin:@[a-zA-Z0-9\.\-_:]+:[0-9]+:[a-zA-Z0-9\.\-_]+",
        r"mongodb://[a-zA-Z0-9\.\-_:]+:[0-9]+/[a-zA-Z0-9\.\-_]+",
        r"mongodb\+srv://[a-zA-Z0-9\.\-_:]+/[a-zA-Z0-9\.\-_]+",
        r"redis://[a-zA-Z0-9\.\-_:]+:[0-9]+",
        r"database_url[^a-zA-Z0-9]([a-zA-Z0-9\.\-_:\/]+)",
        r"db_connection[^a-zA-Z0-9]([a-zA-Z0-9\.\-_:\/]+)",
        r"connection_string[^a-zA-Z0-9]([a-zA-Z0-9\.\-_:\/]+)",
    ],
    
    # Email Addresses
    "Email Addresses": [
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ],
    
    # IP Addresses
    "IP Addresses": [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # IPv4
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",  # IPv6
    ],
    
    # Social Security Numbers (US)
    "SSN": [
        r"\b\d{3}-\d{2}-\d{4}\b",
    ],
    
    # Credit Card Numbers
    "Credit Card Numbers": [
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
    ],
    
    # Phone Numbers
    "Phone Numbers": [
        r"\b\+?1?\s*\(?-*\d{3}\)?-*\s*\d{3}-*\s*\d{4}\b",  # US/Canada
        r"\b\+?[0-9]{1,3}\s*\d{3,4}\s*\d{3,4}\s*\d{3,4}\b",  # International
    ],
    
    # Passwords and Authentication
    "Passwords": [
        r"password[^a-zA-Z0-9]([a-zA-Z0-9\.\-_!@#$%^&*()]{6,32})",
        r"passwd[^a-zA-Z0-9]([a-zA-Z0-9\.\-_!@#$%^&*()]{6,32})",
        r"pwd[^a-zA-Z0-9]([a-zA-Z0-9\.\-_!@#$%^&*()]{6,32})",
        r"pass[^a-zA-Z0-9]([a-zA-Z0-9\.\-_!@#$%^&*()]{6,32})",
    ],
    
    # Authentication Tokens
    "Auth Tokens": [
        r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",  # JWT
        r"[a-zA-Z0-9\-_]{64,}",  # Long random tokens
    ],
    
    # GitHub Tokens
    "GitHub Tokens": [
        r"github_token[^a-zA-Z0-9]([a-zA-Z0-9]{40})",
        r"gh[op]_[A-Za-z0-9_]{36,255}",
    ],
    
    # Stripe API Keys
    "Stripe API Keys": [
        r"sk_live_[0-9a-zA-Z]{24}",
        r"pk_live_[0-9a-zA-Z]{24}",
    ],
    
    # Twilio API Keys
    "Twilio API Keys": [
        r"SK[0-9a-fA-F]{32}",
        r"AC[a-zA-Z0-9]{32}",
    ],
    
    # Slack Tokens
    "Slack Tokens": [
        r"xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32}",
    ],
    
    # Mailgun API Keys
    "Mailgun API Keys": [
        r"key-[0-9a-zA-Z]{32}",
    ],
    
    # Sensitive Comments
    "Sensitive Comments": [
        r"//\s*TODO",
        r"//\s*FIXME",
        r"//\s*HACK",
        r"//\s*XXX",
        r"//\s*BUG",
        r"//\s*NOTE",
        r"<!--\s*TODO",
        r"<!--\s*FIXME",
        r"<!--\s*HACK",
        r"<!--\s*XXX",
        r"<!--\s*BUG",
        r"<!--\s*NOTE",
        r"/\*\s*TODO",
        r"/\*\s*FIXME",
        r"/\*\s*HACK",
        r"/\*\s*XXX",
        r"/\*\s*BUG",
        r"/\*\s*NOTE",
        r"#\s*TODO",
        r"#\s*FIXME",
        r"#\s*HACK",
        r"#\s*XXX",
        r"#\s*BUG",
        r"#\s*NOTE",
    ],
}

# Headers for HTTP requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

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

def check_for_sensitive_data(content, url):
    """
    Check for sensitive data in the content.
    Returns a list of findings.
    """
    findings = []
    
    # Check each pattern category
    for category, patterns in SENSITIVE_DATA_PATTERNS.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get the matched text
                matched_text = match.group(0)
                
                # For some patterns, we want the capture group instead of the full match
                if match.lastindex is not None and match.lastindex > 0:
                    matched_text = match.group(1)
                
                # Get some context around the match
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace(matched_text, f"**{matched_text}**")
                
                # Add to findings
                findings.append({
                    'category': category,
                    'pattern': pattern,
                    'matched_text': matched_text,
                    'context': context,
                    'url': url
                })
    
    return findings

def analyze_with_gemini(url, content, findings):
    """
    Use Gemini API to analyze if the sensitive data findings are significant.
    """
    if not findings:
        return []
    
    # Prepare findings for Gemini
    findings_text = ""
    for i, finding in enumerate(findings):
        findings_text += f"{i+1}. Category: {finding['category']}\n"
        findings_text += f"   Pattern: {finding['pattern']}\n"
        findings_text += f"   Matched Text: {finding['matched_text']}\n"
        findings_text += f"   Context: {finding['context']}\n\n"
    
    prompt = f"""
    I need to analyze if these sensitive data findings from a web page are significant security issues.
    
    URL: {url}
    
    Findings:
    {findings_text}
    
    Please analyze each finding and determine:
    1. Is this likely to be a real sensitive data exposure?
    2. What is the potential security impact?
    3. How severe is this issue (Low, Medium, High)?
    
    For each finding, respond with:
    - Finding #X: [REAL/FALSE POSITIVE]
    - Impact: [Description of impact]
    - Severity: [Low/Medium/High]
    - Recommendation: [Brief recommendation]
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
            "maxOutputTokens": 1024
        }
    }
    
    try:
        response = requests.post(api_url, json=data)
        if response.status_code == 200:
            result = response.json()
            if "candidates" in result and len(result["candidates"]) > 0:
                analysis = result["candidates"][0]["content"]["parts"][0]["text"]
                
                # Parse the analysis to update findings
                lines = analysis.strip().split('\n')
                current_finding = None
                
                for i, finding in enumerate(findings):
                    finding['ai_analysis'] = {
                        'is_real': 'Unknown',
                        'impact': 'Unknown',
                        'severity': 'Unknown',
                        'recommendation': 'Unknown'
                    }
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Finding #'):
                        idx = int(line.split('#')[1].split(':')[0]) - 1
                        if idx < len(findings):
                            current_finding = findings[idx]
                            if 'REAL' in line:
                                current_finding['ai_analysis']['is_real'] = 'Real'
                            elif 'FALSE POSITIVE' in line:
                                current_finding['ai_analysis']['is_real'] = 'False Positive'
                    elif line.startswith('Impact:') and current_finding:
                        current_finding['ai_analysis']['impact'] = line[7:].strip()
                    elif line.startswith('Severity:') and current_finding:
                        current_finding['ai_analysis']['severity'] = line[9:].strip()
                    elif line.startswith('Recommendation:') and current_finding:
                        current_finding['ai_analysis']['recommendation'] = line[15:].strip()
                
                return findings
        
        # If we get here, something went wrong
        for finding in findings:
            finding['ai_analysis'] = {
                'is_real': 'Unknown',
                'impact': 'Unknown',
                'severity': 'Unknown',
                'recommendation': 'Manual review required'
            }
        
        return findings
    
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        
        # If API call fails, return findings without AI analysis
        for finding in findings:
            finding['ai_analysis'] = {
                'is_real': 'Unknown',
                'impact': 'Unknown',
                'severity': 'Unknown',
                'recommendation': 'Manual review required'
            }
        
        return findings

def extract_js_urls(html_content, base_url):
    """Extract JavaScript file URLs from HTML content."""
    js_urls = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Find all script tags with src attribute
    for script in soup.find_all('script', src=True):
        js_url = script['src']
        
        # Handle relative URLs
        if js_url.startswith('//'):
            parsed_base = urllib.parse.urlparse(base_url)
            js_url = f"{parsed_base.scheme}:{js_url}"
        elif not js_url.startswith(('http://', 'https://')):
            js_url = urllib.parse.urljoin(base_url, js_url)
        
        js_urls.append(js_url)
    
    return js_urls

def scan_url_for_sensitive_data(url):
    """Scan a URL for sensitive data exposure."""
    print(f"Scanning URL: {url}")
    findings = []
    
    try:
        # Make the request
        response = requests.get(url, headers=HEADERS, timeout=15)
        
        # Check if the request was successful
        if response.status_code != 200:
            print(f"Failed to fetch {url}: Status code {response.status_code}")
            return []
        
        # Get the content
        content = response.text
        
        # Check for sensitive data in the main content
        main_findings = check_for_sensitive_data(content, url)
        if main_findings:
            findings.extend(main_findings)
        
        # Extract and check JavaScript files
        js_urls = extract_js_urls(content, url)
        for js_url in js_urls:
            try:
                js_response = requests.get(js_url, headers=HEADERS, timeout=10)
                if js_response.status_code == 200:
                    js_findings = check_for_sensitive_data(js_response.text, js_url)
                    if js_findings:
                        findings.extend(js_findings)
            except Exception as e:
                print(f"Error fetching JavaScript file {js_url}: {e}")
        
        # Check for sensitive data in HTTP headers
        headers_str = str(response.headers)
        header_findings = check_for_sensitive_data(headers_str, f"{url} (Headers)")
        if header_findings:
            findings.extend(header_findings)
        
        # Check for sensitive data in cookies
        cookies_str = str(response.cookies)
        cookie_findings = check_for_sensitive_data(cookies_str, f"{url} (Cookies)")
        if cookie_findings:
            findings.extend(cookie_findings)
        
        # If we found any sensitive data, analyze it with Gemini
        if findings:
            findings = analyze_with_gemini(url, content, findings)
        
    except Exception as e:
        print(f"Error scanning URL {url}: {e}")
    
    return findings

def scan_sensitive_data(urls_file_path, max_workers=3):
    """
    Scan URLs for sensitive data exposure.
    
    Args:
        urls_file_path: Path to the file containing URLs
        max_workers: Maximum number of concurrent workers
    
    Returns:
        List of findings
    """
    if not os.path.exists(urls_file_path):
        print(f"File not found: {urls_file_path}")
        return []
    
    urls = extract_urls_from_file(urls_file_path)
    if not urls:
        print("No URLs found in the file.")
        return []
    
    print(f"Found {len(urls)} URLs to scan.")
    
    # Process URLs in smaller batches to show progress
    batch_size = 5
    all_findings = []
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(urls) + batch_size - 1)//batch_size}...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(scan_url_for_sensitive_data, batch))
            
            for result in results:
                all_findings.extend(result)
                
        # Show intermediate results
        if all_findings:
            print(f"Found {len(all_findings)} potential sensitive data exposures so far")
    
    # Save results to file
    output_dir = os.path.dirname(urls_file_path)
    domain = os.path.basename(urls_file_path).split('_')[0]
    output_file = os.path.join(output_dir, f"{domain}_sensitive_data_results.txt")
    
    with open(output_file, 'w') as f:
        if all_findings:
            f.write("Sensitive Data Exposure Scan Results\n")
            f.write("=======================================\n\n")
            
            # Group findings by URL
            findings_by_url = {}
            for finding in all_findings:
                url = finding['url']
                if url not in findings_by_url:
                    findings_by_url[url] = []
                findings_by_url[url].append(finding)
            
            # Write findings grouped by URL
            for url, url_findings in findings_by_url.items():
                f.write(f"URL: {url}\n")
                f.write("-" * len(f"URL: {url}") + "\n\n")
                
                for i, finding in enumerate(url_findings):
                    f.write(f"Finding #{i+1}:\n")
                    f.write(f"  Category: {finding['category']}\n")
                    f.write(f"  Matched Text: {finding['matched_text']}\n")
                    f.write(f"  Context: {finding['context']}\n")
                    
                    # Include AI analysis if available
                    if 'ai_analysis' in finding:
                        f.write(f"  AI Analysis:\n")
                        f.write(f"    Classification: {finding['ai_analysis']['is_real']}\n")
                        f.write(f"    Impact: {finding['ai_analysis']['impact']}\n")
                        f.write(f"    Severity: {finding['ai_analysis']['severity']}\n")
                        f.write(f"    Recommendation: {finding['ai_analysis']['recommendation']}\n")
                    
                    f.write("\n")
                
                f.write("\n" + "=" * 50 + "\n\n")
        else:
            f.write("No sensitive data exposures found.\n")
    
    return all_findings

def test_specific_url(target_url):
    """Test a specific URL for sensitive data exposure."""
    print(f"Testing URL: {target_url}")
    
    findings = scan_url_for_sensitive_data(target_url)
    
    if findings:
        print(f"\nFound {len(findings)} potential sensitive data exposures!")
        for i, finding in enumerate(findings):
            print(f"\nFinding #{i+1}:")
            print(f"  Category: {finding['category']}")
            print(f"  Matched Text: {finding['matched_text']}")
            print(f"  Context: {finding['context']}")
            
            # Include AI analysis if available
            if 'ai_analysis' in finding:
                print(f"  AI Analysis:")
                print(f"    Classification: {finding['ai_analysis']['is_real']}")
                print(f"    Impact: {finding['ai_analysis']['impact']}")
                print(f"    Severity: {finding['ai_analysis']['severity']}")
                print(f"    Recommendation: {finding['ai_analysis']['recommendation']}")
    else:
        print("\nNo sensitive data exposures found.")
    
    return findings

if __name__ == "__main__":
    # For testing the script directly
    import sys
    
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        
        # Check if it's a direct URL test
        if file_path.startswith('http'):
            findings = test_specific_url(file_path)
        else:
            print(f"Scanning file: {file_path}")
            findings = scan_sensitive_data(file_path)
            
            if findings:
                print(f"\nFound {len(findings)} potential sensitive data exposures!")
                # Group findings by URL for display
                findings_by_url = {}
                for finding in findings:
                    url = finding['url']
                    if url not in findings_by_url:
                        findings_by_url[url] = []
                    findings_by_url[url].append(finding)
                
                # Display findings grouped by URL
                for url, url_findings in findings_by_url.items():
                    print(f"\nURL: {url}")
                    print("-" * len(f"URL: {url}"))
                    
                    for i, finding in enumerate(url_findings):
                        print(f"Finding #{i+1}:")
                        print(f"  Category: {finding['category']}")
                        print(f"  Matched Text: {finding['matched_text']}")
                        print(f"  Context: {finding['context']}")
                        
                        # Include AI analysis if available
                        if 'ai_analysis' in finding:
                            print(f"  AI Analysis:")
                            print(f"    Classification: {finding['ai_analysis']['is_real']}")
                            print(f"    Impact: {finding['ai_analysis']['impact']}")
                            print(f"    Severity: {finding['ai_analysis']['severity']}")
                            print(f"    Recommendation: {finding['ai_analysis']['recommendation']}")
            else:
                print("\nNo sensitive data exposures found.")
    else:
        print("Usage: python sensitive_data_test.py <path_to_urls_file_or_direct_url>")
        print("Examples:")
        print("  python sensitive_data_test.py C:\\Users\\begad\\OneDrive\\Desktop\\Recon-test\\crawler\\example.com_urls.txt")
        print("  python sensitive_data_test.py http://example.com")