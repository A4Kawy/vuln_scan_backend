import os
import subprocess
import time
import sys
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

def save_to_file(file_path, data):
    """
    Save data to a file.
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as file:
        file.write("\n".join(data))
    return f"Data saved to {file_path}"

def find_subdomain_file(domain, search_path="."):
    """
    Search for the file {domain}_all_subdomains.txt in the given directory and its subdirectories.
    """
    for root, dirs, files in os.walk(search_path):
        for file in files:
            if file == f"{domain}_all_subdomains.txt":
                return os.path.join(root, file)
    return None

def test_connectivity(subdomain, retries=2, delay=2):
    """
    Test connectivity to the subdomain using requests to verify if it's reachable.
    Supports both HTTP and HTTPS.
    """
    protocols = ["http", "https"]
    for protocol in protocols:
        url = f"{protocol}://{subdomain}"
        for attempt in range(retries):
            try:
                response = requests.get(url, timeout=10, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
                })
                if response.status_code == 200:
                    print(f"[+] Connectivity test passed for {url}")
                    return protocol
                else:
                    print(f"[-] Connectivity test failed for {url}: Status code {response.status_code}")
            except requests.RequestException as e:
                print(f"[-] Connectivity test failed for {url}: {str(e)}")
            time.sleep(delay)
    print(f"[!] All connectivity tests failed for {subdomain}")
    return None

def simple_crawler(subdomain, max_depth=3):
    """
    A simple crawler using requests and BeautifulSoup as a fallback if Katana fails.
    Supports both HTTP and HTTPS.
    """
    protocol = test_connectivity(subdomain)
    if not protocol:
        return [], []
    
    base_url = f"{protocol}://{subdomain}"
    visited = set()
    urls_with_params = []
    urls_without_params = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"}

    def crawl(url, depth):
        if depth > max_depth or url in visited or len(visited) > 100:
            return
        visited.add(url)
        print(f"[CRAWL] Crawling: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200:
                return
            if '?' in url:
                urls_with_params.append(url)
            else:
                urls_without_params.append(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(base_url, href)
                if absolute_url.startswith(base_url) and absolute_url not in visited:
                    crawl(absolute_url, depth + 1)
            time.sleep(1)
        except requests.RequestException as e:
            print(f"[CRAWL] Error crawling {url}: {str(e)}")

    crawl(base_url, 0)
    return urls_with_params, urls_without_params

def run_katana(input_file, output_dir, domain):
    """
    Run the Katana tool directly on a list of subdomains and save the discovered URLs.
    Falls back to simple_crawler if Katana fails.
    """
    try:
        # تنظيف ملفات النتايج القديمة
        crawler_dir = os.path.dirname(os.path.abspath(__file__))
        params_file = os.path.join(crawler_dir, f"{domain}_params.txt")
        others_file = os.path.join(crawler_dir, f"{domain}_others.txt")
        if os.path.exists(params_file):
            os.remove(params_file)
        if os.path.exists(others_file):
            os.remove(others_file)

        with open(input_file, 'r') as file:
            subdomains = file.readlines()

        # فلترة النطاقات الفرعية بناءً على النطاق المفحوص
        valid_subdomains = [
            s.strip() for s in subdomains
            if s.strip() and domain in s and not any(x in s for x in ["edu-rost", "blogger.com"])
        ]
        if not valid_subdomains:
            print(f"[!] No valid subdomains found for {domain} after filtering.", file=sys.stderr)
            return {
                "params_file": "",
                "others_file": "",
                "total_urls": 0,
                "urls_with_params": 0,
                "urls_without_params": 0
            }

        all_urls = []
        processed_count = 0
        total_subdomains = len(valid_subdomains)
        
        for subdomain in valid_subdomains:
            processed_count += 1
            print(f"Processing {processed_count}/{total_subdomains}: {subdomain}")
            
            # اختبار الاتصال
            protocol = test_connectivity(subdomain)
            if not protocol:
                print(f"[!] Skipping crawling for {subdomain} due to connectivity failure")
                continue

            try:
                # Run Katana with HTTP/HTTPS, User-Agent, and increased timeout
                command = [
                    "katana",
                    "-u", f"{protocol}://{subdomain}",
                    "-timeout", "100",
                    "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
                    "-c", "5",
                    "-no-redirect",
                    "-d", "2"  
                ]
                print(f"[DEBUG] Running command: {' '.join(command)}")
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                # Add the discovered links to the all_urls list if valid
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if output:
                        discovered_urls = output.splitlines()
                        print(f"Found {len(discovered_urls)} URLs for {subdomain}")
                        all_urls.extend(discovered_urls)
                    else:
                        print(f"No URLs found for {subdomain}")
                else:
                    print(f"[ERROR] Katana failed for {subdomain}: {result.stderr}")
                    # Fallback to simple_crawler
                    print(f"[FALLBACK] Trying simple crawler for {subdomain}")
                    params_urls, no_params_urls = simple_crawler(subdomain)
                    all_urls.extend(params_urls)
                    all_urls.extend(no_params_urls)
                
                time.sleep(2)
                
            except subprocess.TimeoutExpired as e:
                print(f"[ERROR] Timeout occurred while processing {subdomain}: {str(e)}")
                print(f"[FALLBACK] Trying simple crawler for {subdomain}")
                params_urls, no_params_urls = simple_crawler(subdomain)
                all_urls.extend(params_urls)
                all_urls.extend(no_params_urls)
            except FileNotFoundError:
                print("[ERROR] Katana tool not found. Please install it and add to PATH.")
                print(f"[FALLBACK] Trying simple crawler for {subdomain}")
                params_urls, no_params_urls = simple_crawler(subdomain)
                all_urls.extend(params_urls)
                all_urls.extend(no_params_urls)
            except Exception as e:
                print(f"[ERROR] Unexpected error while processing {subdomain}: {str(e)}")
                print(f"[FALLBACK] Trying simple crawler for {subdomain}")
                params_urls, no_params_urls = simple_crawler(subdomain)
                all_urls.extend(params_urls)
                all_urls.extend(no_params_urls)

        # Remove duplicates and empty lines from the result
        all_urls = list(dict.fromkeys([url for url in all_urls if url.strip()]))
        print(f"Total URLs discovered: {len(all_urls)}")

        # Separate URLs with parameters and others
        urls_with_params = [url for url in all_urls if '?' in url]
        urls_without_params = [url for url in all_urls if '?' not in url]

        # Save URLs to the crawler folder
        save_to_file(params_file, urls_with_params)
        save_to_file(others_file, urls_without_params)

        return {
            "params_file": params_file,
            "others_file": others_file,
            "total_urls": len(all_urls),
            "urls_with_params": len(urls_with_params),
            "urls_without_params": len(urls_without_params)
        }

    except Exception as e:
        import traceback
        return f"An unexpected error occurred: {e}\n{traceback.format_exc()}"