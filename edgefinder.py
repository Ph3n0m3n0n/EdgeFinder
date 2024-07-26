#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os

def print_ascii_art():
    print(r"""
 _____    _            _____ _           _           
 | ____|__| | __ _  ___|  ___(_)_ __   __| | ___ _ __ 
 |  _| / _` |/ _` |/ _ | |_  | | '_ \ / _` |/ _ | '__|
 | |__| (_| | (_| |  __|  _| | | | | | (_| |  __| |   
 |_____\__,_|\__, |\___|_|   |_|_| |_|\__,_|\___|_|   
             |___/                                     
    """)

def parse_args():
    parser = argparse.ArgumentParser(description="EdgeFinder - A tool for processing domain and IP files.")
    parser.add_argument('-f', '--file', type=str, required=True, help='File path containing domains or IPs')
    parser.add_argument('-t', '--type', type=str, choices=['domains', 'ips'], required=True, help='Type of data in the file')
    parser.add_argument('-n', '--nslookup', action='store_true', help='Perform nslookup on domains')
    parser.add_argument('-s', '--nmap', action='store_true', help='Perform nmap scan on IPs')
    parser.add_argument('-o', '--output', type=str, help='Output file name for results')
    return parser.parse_args()

def nslookup(domain):
    try:
        result = subprocess.check_output(['nslookup', domain], stderr=subprocess.STDOUT, text=True)
        lines = result.splitlines()
        ip_line = next((line for line in lines if 'Address:' in line), "Lookup failed")
        return ip_line.split()[-1] if ip_line != "Lookup failed" else ip_line
    except subprocess.CalledProcessError:
        return "Lookup failed"

def nmap_scan(ip, output_file):
    try:
        output_base = output_file.rsplit('.', 1)[0]  # Remove extension for -oA
        result = subprocess.check_output(['nmap', '-sS', '-A', '-oA', output_base, ip], stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError:
        return "Nmap scan failed"

def sublist3r_scan(domain, output_file):
    try:
        result = subprocess.check_output(['sublist3r', '-d', domain, '-o', output_file], stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError:
        return "Sublist3r scan failed"

def process_file(file_path, data_type, perform_nslookup, perform_nmap, output_file):
    if not os.path.isfile(file_path):
        print("File not found!")
        sys.exit(1)
    
    with open(file_path, 'r') as file:
        lines = [line.strip() for line in file.readlines()]

    results = []
    if perform_nslookup and data_type == 'domains':
        for line in lines:
            ip = nslookup(line)
            results.append(f"{line} -> {ip}")

    if data_type == 'domains':
        if not output_file:
            print("Output file name is required for Sublist3r scan.")
            sys.exit(1)
        for line in lines:
            scan_result = sublist3r_scan(line, output_file)
            results.append(f"Sublist3r result for {line}:\n{scan_result}")

    if perform_nmap and data_type == 'ips':
        if not output_file:
            print("Output file name is required for nmap scan.")
            sys.exit(1)
        for line in lines:
            scan_result = nmap_scan(line, output_file)
            results.append(f"Scan result for {line}:\n{scan_result}")

    if results and output_file:
        with open(output_file, 'w') as out_file:
            out_file.write("\n".join(results))
        print(f"Results written to {output_file}")
    else:
        print("\n".join(results))

def main():
    print_ascii_art()
    args = parse_args()
    if args.nslookup and not args.output:
        print("Output file name is required when using nslookup.")
        sys.exit(1)
    process_file(args.file, args.type, args.nslookup, args.nmap, args.output)

if __name__ == "__main__":
    main()
