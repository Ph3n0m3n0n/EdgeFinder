#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import glob

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
    parser = argparse.ArgumentParser(
        description="EdgeFinder - A tool for processing and organizing externally facing domains and IPs.",
        epilog="Example usage:\n"
               "  ./edgefinder.py -f list_of_domains.txt -n -o results.out\n"
               "  ./edgefinder.py -s single_domain.com -o results.out\n"
               "  ./edgefinder.py -i single_ip_address\n"
               "  ./edgefinder.py -d /path/to/nmap/results"
    )
    parser.add_argument(
        '-f', '--file', type=str,
        help='Specify file path to a file containing domains or IPs.'
    )
    parser.add_argument(
        '-n', '--nslookup', action='store_true',
        help='Performs nslookup on a list of domains and outputs results to a .out file.'
    )
    parser.add_argument(
        '-s', '--single', type=str,
        help='Enter a single domain for sublist3r scan. Results output to a .out file.'
    )
    parser.add_argument(
        '-i', '--ip', type=str,
        help='Enter a single IP address for nmap scan (default flags are: -sS -A, default output -oA)'
    )
    parser.add_argument(
        '-o', '--output', type=str,
        help='Output file name for results'
    )
    parser.add_argument(
        '-d', '--directory', type=str,
        help='Parent directory containing .xml files for msfconsole import'
    )
    return parser.parse_args()

def nslookup(domain):
    try:
        result = subprocess.check_output(['nslookup', domain], stderr=subprocess.STDOUT, text=True)
        lines = result.splitlines()
        ip_line = next((line for line in lines if 'Address:' in line), "Lookup failed")
        return ip_line.split()[-1] if ip_line != "Lookup failed" else ip_line
    except subprocess.CalledProcessError as e:
        print(f"Nslookup failed for {domain}: {e.output}")
        return "Lookup failed"

def nmap_scan(ip, output_file):
    try:
        output_base = output_file.rsplit('.', 1)[0]  # Remove extension for -oA
        result = subprocess.check_output(['nmap', '-sS', '-A', '-oA', output_base, ip], stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed for {ip}: {e.output}")
        return "Nmap scan failed"

def sublist3r_scan(domain, output_file):
    try:
        result = subprocess.check_output(['sublist3r', '-d', domain, '-o', output_file], stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Sublist3r scan failed for {domain}: {e.output}")
        return "Sublist3r scan failed"

def import_to_msfconsole(directory):
    xml_files = glob.glob(os.path.join(directory, "*.xml"))
    if not xml_files:
        print("No .xml files found in the specified directory.")
        return
    
    for xml_file in xml_files:
        try:
            subprocess.check_output(['msfconsole', '-q', '-x', f"db_import {xml_file}; exit"], stderr=subprocess.STDOUT, text=True)
            print(f"Imported {xml_file} into msfconsole database.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to import {xml_file} into msfconsole: {e.output}")

def process_file(file_path, perform_nslookup, output_file):
    if not os.path.isfile(file_path):
        print("File not found!")
        sys.exit(1)
    
    with open(file_path, 'r') as file:
        lines = [line.strip() for line in file.readlines()]

    results = []
    if perform_nslookup:
        # Check if lines are domains
        if all('.' in line for line in lines):
            for line in lines:
                print(f"Performing nslookup for {line}...")
                ip = nslookup(line)
                results.append(f"{line} -> {ip}")
        else:
            print("Nslookup cannot be performed because the file contains IP addresses instead of domains.")
            sys.exit(1)
    else:
        # Check if lines are IPs
        if all(line.replace('.', '').isdigit() for line in lines):
            if not output_file:
                print("Output file name is required for nmap scan.")
                sys.exit(1)
            for line in lines:
                print(f"Performing nmap scan for {line}...")
                scan_result = nmap_scan(line, output_file)
                results.append(f"Scan result for {line}:\n{scan_result}")
        else:
            print("Nmap scan cannot be performed because the file contains domains instead of IP addresses.")
            sys.exit(1)

    if results and output_file:
        with open(output_file, 'w') as out_file:
            out_file.write("\n".join(results))
        print(f"Results written to {output_file}")
    else:
        print("\n".join(results))

def main():
    print_ascii_art()
    args = parse_args()

    if args.single:
        output_file = args.output or f"{args.single}.out"
        print(f"Performing sublist3r scan for {args.single}...")
        result = sublist3r_scan(args.single, output_file)
        print(result)
        return

    if args.ip:
        output_file = args.output or f"{args.ip}.out"
        print(f"Performing nmap scan for {args.ip}...")
        result = nmap_scan(args.ip, output_file)
        print(result)
        return

    if args.directory:
        print(f"Importing .xml files from {args.directory} into msfconsole database...")
        import_to_msfconsole(args.directory)
        return

    if args.file:
        process_file(args.file, args.nslookup, args.output)
    else:
        print("Please provide a valid file path, or a single domain/IP address, or a parent directory.")
        sys.exit(1)

if __name__ == "__main__":
    main()
