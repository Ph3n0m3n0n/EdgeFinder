#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import traceback

def print_ascii_art():
    print(r"""
 _____    _            _____ _           _           
 | ____|__| | __ _  ___|  ___(_)_ __   __| | ___ _ __ 
 |  _| / _` |/ _` |/ _ | |_  | | '_ \ / _` |/ _ | '__|
 | |__| (_| | (_| |  __|  _| | | | | | (_| |  __| |   
 |_____\__,_|\__, |\___|_|   |_|_| |_|\__,_|\___|_|   
             |___/                                          
    """)

def check_dependencies():
    dependencies = [
        (['python3', '--version'], 'python3'),
        (['pip3', '--version'], 'python3-pip'),
        (['nmap', '--version'], 'nmap'),
        (['nslookup', '--version'], 'dnsutils'),
        (['msfconsole', '--version'], 'metasploit-framework'),
        (['sublist3r', '--version'], 'sublist3r')
    ]
    for command, package in dependencies:
        try:
            subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=3)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            print(f"{package} is not installed. Please install it manually.")

def parse_args():
    parser = argparse.ArgumentParser(description="EdgeFinder - A tool for processing domain and IP files.")
    parser.add_argument('-f', '--file', required=True, type=str, help='File path containing domains or IPs')
    parser.add_argument('-t', '--type', required=True, type=str, choices=['domains', 'ips'], help='Type of data in the file')
    parser.add_argument('-n', '--nslookup', action='store_true', help='Perform nslookup on domains')
    parser.add_argument('-o', '--output', type=str, help='Output file name for nslookup results')
    parser.add_argument('--nmap', action='store_true', help='Perform nmap scan on IPs')
    parser.add_argument('--ip-file', type=str, help='File path containing IP addresses for nmap scan')
    parser.add_argument('-q', '--quiet', action='store_true', help='Run without stdout output (quiet mode)')
    return parser.parse_args()

def nslookup(domain):
    try:
        result = subprocess.check_output(['nslookup', domain], stderr=subprocess.STDOUT, text=True)
        return result.split()[-1]
    except subprocess.CalledProcessError as e:
        return f"Lookup failed: {e.output.strip()}"

def sublist3r_scan(domain):
    try:
        result = subprocess.check_output(['sublist3r', '-d', domain], stderr=subprocess.STDOUT, text=True)
        return result.splitlines()
    except subprocess.CalledProcessError as e:
        return f"Sublist3r scan failed: {e.output.strip()}"

def nmap_scan(ip, flags, output_file, output_format):
    command = ['nmap'] + flags.split() + [ip]
    if output_file:
        command += [f'-{output_format}', output_file]
    try:
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        return result if not output_file else None
    except subprocess.CalledProcessError as e:
        return f"Nmap scan failed: {e.output.strip()}"

def process_file(args):
    while not os.path.isfile(args.file):
        print("File not found!")
        args.file = input("Please enter a valid file path or type 'exit' or 'quit' to exit: ")
        if args.file.lower() in ['exit', 'quit']:
            sys.exit(0)
    
    with open(args.file, 'r') as file:
        lines = file.readlines()

    if args.type == 'domains' and args.nslookup:
        with open(args.output, 'w') as out_file:
            for domain in lines:
                result = nslookup(domain.strip())
                out_file.write(f"{domain.strip()} -> {result}\n")
                if args.file.lower() in ['exit', 'quit']:
                 sys.exit(0)

    if args.nmap:
        for ip in lines:
            ip = ip.strip()
            result = nmap_scan(ip, '-sS -A', args.ip_file, 'oA')
            if result and not args.quiet:
                print(f"Nmap scan result for {ip}:\n{result}")

def main():
    print_ascii_art()
    check_dependencies()
    args = parse_args()
    process_file(args)

if __name__ == "__main__":
    main()
