# Python 3
# LinkFinder++
# By Marco Figueroa @marcofigueroa on twitter

import os
import sys
import subprocess
import re
import jsbeautifier
import html
import base64
import ssl
import xml.etree.ElementTree
from urllib.parse import urlparse
from gzip import GzipFile
from urllib.request import Request, urlopen


os.environ["BROWSER"] = "open"

# Define readBytesCustom
try:
    from StringIO import StringIO
    readBytesCustom = StringIO
except ImportError:
    from io import BytesIO
    readBytesCustom = BytesIO

# Regex used by linkfinder++
regex_str = r"""
  (?:"|')
  (
    ((?:[a-zA-Z]{1,10}://|//)
    [^"'/]{1,}\.
    [a-zA-Z]{2,}[^"']{0,})
    |
    ((?:/|\.\./|\./)
    [^"'><,;| *()(%%$^/\\\[\]]
    [^"'><,;|()]{1,})
    |
    ([a-zA-Z0-9_\-/]{1,}/
    [a-zA-Z0-9_\-/.]{1,}
    \.(?:[a-zA-Z]{1,4}|action)
    (?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-/]{1,}/
    [a-zA-Z0-9_\-/]{3,}
    (?:[\?|#][^"|']{0,}|))
    |
    ([a-zA-Z0-9_\-]{1,}
    \.(?:php|asp|aspx|jsp|json|
         action|html|js|txt|xml)
    (?:[\?|#][^"|']{0,}|))
  )
  (?:"|')
"""


beautifier_options = jsbeautifier.default_options()
beautifier_options.indent_size = 4
beautifier_options.space_in_empty_paren = True

def send_request(url):
    '''
    Send requests with Requests
    '''
    q = Request(url)
    q.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
    q.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
    q.add_header('Accept-Language', 'en-US,en;q=0.8')
    q.add_header('Accept-Encoding', 'gzip')

    try:
        sslcontext = ssl.create_default_context()
        response = urlopen(q, timeout=30, context=sslcontext)  # Increased timeout to 30 seconds
    except Exception as e:
        print(f"Error during request: {e}")
        return None

    if response.info().get('Content-Encoding') == 'gzip':
        data = GzipFile(fileobj=readBytesCustom(response.read())).read()
    elif response.info().get('Content-Encoding') == 'deflate':
        data = response.read().read()
    else:
        data = response.read()

    return data.decode('utf-8', 'replace')

def save_js_file(url, content, save_dir):
    parsed_url = urlparse(url)
    js_filename = os.path.basename(parsed_url.path)
    js_path = os.path.join(save_dir, js_filename)
    with open(js_path, 'w', encoding='utf-8') as f:
        f.write(content)
    return js_path

def parser_file(content, regex_str, mode=1):
    '''
    Parse Input
    content:    string of content to be searched
    regex_str:  string of regex (The link should be in the group(1))
    mode:       mode of parsing. Set 1 to include surrounding contexts in the result
    '''
    if mode == 1:
        # Beautify
        content = jsbeautifier.beautify(content, beautifier_options)
    regex = re.compile(regex_str, re.VERBOSE)
    all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, content)]
    items = getContext(all_matches, content, context_delimiter_str="\n")
    return items

def getContext(list_matches, content, include_delimiter=0, context_delimiter_str="\n"):
    '''
    Parse Input
    list_matches:       list of tuple (link, start_index, end_index)
    content:            content to search for the context
    include_delimiter   Set 1 to include delimiter in context
    '''
    items = []
    for m in list_matches:
        match_str = m[0]
        match_start = m[1]
        match_end = m[2]
        context_start_index = match_start
        context_end_index = match_end
        delimiter_len = len(context_delimiter_str)
        content_max_index = len(content) - 1

        while content[context_start_index] != context_delimiter_str and context_start_index > 0:
            context_start_index = context_start_index - 1

        while content[context_end_index] != context_delimiter_str and context_end_index < content_max_index:
            context_end_index = context_end_index + 1

        if include_delimiter:
            context = content[context_start_index: context_end_index]
        else:
            context = content[context_start_index + delimiter_len: context_end_index]

        item = {
            "link": match_str,
            "context": context
        }
        items.append(item)

    return items

def save_interesting_js(url, endpoints, save_dir):
    parsed_url = urlparse(url)
    js_filename = os.path.basename(parsed_url.path)
    interesting_js_filename = os.path.join(save_dir, f"{js_filename}.interestingjs.txt")
    with open(interesting_js_filename, 'w', encoding='utf-8') as f:
        for endpoint in endpoints:
            f.write(html.escape(endpoint["link"]).encode('ascii', 'ignore').decode('utf8') + '\n')
    
    # Grep for 'api' and 'dev' and save to respective files
    grep_and_save(interesting_js_filename, 'api', 'api')
    grep_and_save(interesting_js_filename, 'dev', 'dev')

def grep_and_save(file_path, search_term, output_suffix):
    output_file_path = file_path.replace(".interestingjs.txt", f".interestingjs.{output_suffix}.txt")
    matches_found = False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            for line in lines:
                if search_term in line:
                    outfile.write(line)
                    matches_found = True

        if not matches_found:
            os.remove(output_file_path)
    except Exception as e:
        print(f"Error processing file {file_path} for term {search_term}: {e}")

def cli_output(endpoints):
    '''
    Output to CLI
    '''
    for endpoint in endpoints:
        print(html.escape(endpoint["link"]).encode('ascii', 'ignore').decode('utf8'))

def extract_inline_js_from_html(js_file_path):
    try:
        with open(js_file_path, 'r', encoding='utf-8') as file:
            html_content = file.read()

        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL)
        inline_js = "\n".join(scripts)
        beautified_inline_js = jsbeautifier.beautify(inline_js, beautifier_options)
        return beautified_inline_js
    except Exception as e:
        print(f"Error extracting inline JS: {e}")
        return None

def extract_and_combine_js(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            content = file.read()

        combined_content = content

        if input_file.endswith('.html'):
            inline_js = extract_inline_js_from_html(input_file)
            if inline_js:
                combined_content += '\n' + inline_js

        formatted_content = jsbeautifier.beautify(combined_content, beautifier_options)
        
        with open(output_file, 'w', encoding='utf-8') as output:
            output.write(formatted_content)
        
        print(f"JavaScript and inline JavaScript extracted and saved to {output_file}")
    except Exception as e:
        print(f"Error extracting and combining JS: {e}")

def process_js_file(js_file, save_dir):
    basename = os.path.basename(js_file)
    formatted_js_file = os.path.join(save_dir, f"formatted_{basename}")
    
    # Step 1: Run linkfinder++
    try:
        with open(js_file, 'r', encoding='utf-8') as file:
            js_content = file.read()

        endpoints = parser_file(js_content, regex_str)
        save_interesting_js(js_file, endpoints, save_dir)
        cli_output(endpoints)
    except Exception as e:
        print(f"Error running linkfinder++: {e}")
    
    # Step 2: Extract and combine JS
    extract_and_combine_js(js_file, formatted_js_file)
    
    # Step 3: Run ESLint with the --fix option on the formatted file
    try:
        eslint_config_path = os.path.join(os.path.dirname(__file__), 'eslint.config.js')
        eslint_output = subprocess.run(['eslint', formatted_js_file, '--fix', '--config', eslint_config_path], capture_output=True, text=True)
        print(eslint_output.stdout)
        print(eslint_output.stderr)
    except Exception as e:
        print(f"Error running ESLint: {e}")

def read_urls_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            urls = [line.strip() for line in file if line.strip() and line.strip().endswith('.js')]
        return urls
    except Exception as e:
        print(f"Error reading URLs from file: {e}")
        return []
    


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <input_js_link_or_file_or_txt_file_with_links>")
        sys.exit(1)
    
    input_path = sys.argv[1]
    
    if not input_path:
        print("Usage: python3 script.py <input_js_link_or_file_or_txt_file_with_links>")
        sys.exit(1)

    # Check if the input is a text file with links
    if os.path.isfile(input_path) and input_path.endswith(('.out', '.txt')):
        urls = read_urls_from_file(input_path)
    else:
        urls = [input_path]

    for url in urls:
        parsed_url = urlparse(url)
        domain_name = parsed_url.netloc.replace('.', '_')
        input_dir = os.path.dirname(input_path)
        # Create directory based on domain name
        save_dir = os.path.join(input_dir, domain_name)
        os.makedirs(save_dir, exist_ok=True)
        
        # Download JS file
        if parsed_url.scheme in ('http', 'https'):
            js_content = send_request(url)
            if js_content is None:
                print(f"Failed to download the JS file from {url}. Skipping...")
                continue
            js_file_path = save_js_file(url, js_content, save_dir)
        else:
            js_file_path = url

        process_js_file(js_file_path, save_dir)

if __name__ == "__main__":
    main()
