# linkfinder++ JavaScript Link Finder and Analyzer

This program stand on the shoulders of linkfinder's original creator Gerben Javado, many of the functions he's built are in this code he did an amazing job with the original code the upgrades I've made I feel were inhancements I believe that were needed. 

linkfinder++ processes JavaScript files and extracts interesting links using regex patterns. It can handle individual JavaScript files, URLs, or a text file containing multiple JavaScript URLs. The program downloads the JavaScript files, formats them, and runs ESLint for code quality checks. Additionally, it identifies and saves links containing specific terms like `api` and `dev` `interesting texts that it finds`.

## Features

- Downloads and processes JavaScript files from URLs.
- Extracts and formats inline JavaScript from HTML files.
- Uses regex patterns to find interesting links in JavaScript files.
- Saves extracted links to separate files.
- Filters links containing specific terms (`api` and `dev`) and saves them to separate files.
- Runs ESLint with the `--fix` option on the formatted JavaScript files for easier auditing of code.

## Requirements

- Python 3.x
- Required Python packages:
  - `jsbeautifier`
  - `requests`

## Usage

1. Clone the repository or download the script.
2. Install the required Python packages:

```bash
pip install jsbeautifier requests

or

pipenv install
pipenv shell

$python3 linkfinder++.py <input_js_link_or_file_or_txt_file_with_links>
$python3 linkfinder++.py https://example.com/script.js
$python3 linkfinder++.py urls.txt
