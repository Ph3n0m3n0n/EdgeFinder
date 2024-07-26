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

## Features

- **Nslookup**: Perform nslookup on a list of domains.
- **Nmap Scan**: Perform nmap scans on a list of IP addresses.
- **Sublist3r Scan**: Scan a single domain using sublist3r.
- **msfconsole Import**: Import XML files into the msfconsole database.

## Usage

### Command-line Arguments

```text
usage: edgefinder.py [-h] [-f FILE] [-n] [-s SINGLE] [-i IP] [-o OUTPUT] [-d DIRECTORY]

EdgeFinder - A tool for processing and organizing externally facing domains and IPs.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Specify file path to a file containing domains or IPs.
  -n, --nslookup        Performs nslookup on a list of domains and outputs results to a .out file.
  -s SINGLE, --single SINGLE
                        Enter a single domain for sublist3r scan. Results output to a .out file.
  -i IP, --ip IP        Enter a single IP address for nmap scan (default flags are: -sS -A, default output -oA)
  -o OUTPUT, --output OUTPUT
                        Output file name for results
  -d DIRECTORY, --directory DIRECTORY
                        Parent directory containing .xml files for msfconsole import

### Running the Script

```sh
python3 edgefinder.py -h 

