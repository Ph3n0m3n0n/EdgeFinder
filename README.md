# EdgeFinder

EdgeFinder is a comprehensive command-line tool designed to process domains, IPs & files. It supports various network reconnaissance and information gathering tasks by leveraging utilities like nslookup, nmap, and Sublist3r. This tool is particularly useful for security professionals and network administrators who need to automate the collection of "edge" assets for security assessments.

## Prerequisites

Ensure the following dependencies are installed on your system:
- Python 3
- pip3 (Python package installer)
- nmap
- dnsutils (for nslookup)
- metasploit-framework (for msfconsole)
- Sublist3r

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Ph3n0m3n0n/EdgeFinder.git
    cd EdgeFinder
    ```

## Usage

### Command Line Arguments

- `-f, --file`: File path containing domains or IPs
- `-t, --type`: Type of data in the file (`domains`, `ips`, `both`)
- `-n, --nslookup`: Perform nslookup on domains
- `-o, --output`: Output file name for nslookup results
- `--nmap`: Perform nmap scan on IPs
- `--ip-file`: File path containing IP addresses for nmap scan
- `-q, --quiet`: Run without stdout output (quiet mode)

### Running the Script

```sh
python3 edgefinder.py

