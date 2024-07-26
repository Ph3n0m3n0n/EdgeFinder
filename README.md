# EdgeFinder

EdgeFinder is a tool for processing domain and IP files. It includes functionality for performing nslookup and nmap scans.

## Prerequisites

Ensure the following dependencies are installed on your system:
- Python 3
- pip (Python package installer)
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

2. Install Python dependencies:
    ```sh
    pip install -r requirements.txt
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

