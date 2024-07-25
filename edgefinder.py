import argparse
import subprocess
import sys
import os

def print_ascii_art():
    print(r"""
                                                                                                                                        
                    _______                                                           _______                                            
       __.....__    \  ___ `'.                 __.....__               .--.   _..._   \  ___ `'.         __.....__                       
   .-''         '.   ' |--.\  \    .--./)  .-''         '.        _.._ |__| .'     '.  ' |--.\  \    .-''         '.                     
  /     .-''"'-.  `. | |    \  '  /.''\\  /     .-''"'-.  `.    .' .._|.--..   .-.   . | |    \  '  /     .-''"'-.  `. .-,.--.           
 /     /________\   \| |     |  '| |  | |/     /________\   \   | '    |  ||  '   '  | | |     |  '/     /________\   \|  .-. |          
 |                  || |     |  | \`-' / |                  | __| |__  |  ||  |   |  | | |     |  ||                  || |  | |          
 \    .-------------'| |     ' .' /("'`  \    .-------------'|__   __| |  ||  |   |  | | |     ' .'\    .-------------'| |  | |          
  \    '-.____...---.| |___.' /'  \ '---. \    '-.____...---.   | |    |  ||  |   |  | | |___.' /'  \    '-.____...---.| |  '-           
   `.             .'/_______.'/    /'""'.\ `.             .'    | |    |__||  |   |  |/_______.'/    `.             .' | |               
     `''-...... -'  \_______|/    ||     ||  `''-...... -'      | |        |  |   |  |\_______|/       `''-...... -'   | |               
                                  \'. __//                      | |        |  |   |  |                                 |_|               
                                   `'---'                       |_|        '--'   '--'                                                   
    """)

def check_dependency(command, package_name):
    try:
        print(f"Checking {package_name}...")
        subprocess.check_output(command, stderr=subprocess.STDOUT, text=True, timeout=3)
        print(f"{package_name} is installed.")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"{package_name} is not installed or validation took too long. Error: {e}. Please install it manually.")

def check_dependencies():
    dependencies = [
        (['python3', '--version'], 'python3'),
        (['pip3', '--version'], 'python3-pip'),
        (['nmap', '--version'], 'nmap'),
        (['nslookup', '--version'], 'dnsutils'),
        (['msfconsole', '--version'], 'metasploit-framework'),
        (['sublist3r', '--version'], 'sublist3r')
    ]
    
    for command, package_name in dependencies:
        check_dependency(command, package_name)
    print("Dependency check completed.")

def parse_args():
    parser = argparse.ArgumentParser(
        description="EdgeFinder - A tool for processing domain and IP files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-f', '--file', type=str, help='File path containing domains or IPs')
    parser.add_argument('-t', '--type', type=str, choices=['domains', 'ips', 'both'], help='Type of data in the file')
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
        return f"Lookup failed: {e}"

def sublist3r_scan(domain):
    try:
        result = subprocess.check_output(['sublist3r', '-d', domain], stderr=subprocess.STDOUT, text=True)
        return result.splitlines()
    except subprocess.CalledProcessError as e:
        return [f"Sublist3r scan failed: {e}"]

def nmap_scan(ip, flags, output_file, output_format):
    command = ['nmap'] + flags.split() + [ip]
    if output_file:
        if output_format == 'oA':
            command += ['-oA', output_file]
        elif output_format == 'oN':
            command += ['-oN', output_file]
        elif output_format == 'oX':
            command += ['-oX', output_file]
    try:
        result = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        if not output_file:
            return result
    except subprocess.CalledProcessError as e:
        return f"Nmap scan failed: {e}"

def process_file(file_path, data_type, perform_nslookup, output_file, perform_nmap, nmap_flags, nmap_output_file, nmap_output_format, quiet_mode):
    if not os.path.isfile(file_path):
        if not quiet_mode:
            print("File not found!")
        sys.exit(1)
    
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    if data_type == 'domains' and perform_nslookup:
        perform_nslookup_on_file(file_path)
    
    if perform_nmap:
        valid_ips = True
        for line in lines:
            ip = line.strip()
            if not validate_ip(ip):
                valid_ips = False
                break
        
        if not valid_ips:
            if not quiet_mode:
                print("The IP file format is incorrect. Each line should contain a valid IP address.")
            choice = input("Do you want to exit or enter another file name? (exit/enter): ").strip().lower()
            if choice == 'enter':
                new_ip_file = input("Please enter the new IP file name: ").strip()
                process_file(new_ip_file, data_type, perform_nslookup, output_file, perform_nmap, nmap_flags, nmap_output_file, nmap_output_format, quiet_mode)
            else:
                sys.exit(1)
        
        for ip in lines:
            ip = ip.strip()
            result = nmap_scan(ip, nmap_flags, nmap_output_file, nmap_output_format)
            if not nmap_output_file and not quiet_mode:
                print(f"Nmap scan result for {ip}:\n{result}")
        
        if nmap_output_format == 'oX' and nmap_output_file:
            prompt_msfconsole_import(nmap_output_file, quiet_mode)

def validate_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True

def prompt_msfconsole_import(output_file, quiet_mode):
    print("\nNote: msfconsole must be installed and the database must be initiated.")
    print("To initiate the database, run 'msfdb init'.")
    
    import_choice = input("Do you want to import the nmap .xml results to the msfconsole database? (y/n): ").strip().lower()
    if import_choice == 'y':
        try:
            subprocess.check_call(['msfconsole', '-x', f'db_import {output_file}.xml; exit'])
        except subprocess.CalledProcessError as e:
            if not quiet_mode:
                print(f"Failed to import nmap results to msfconsole database: {e}")

def initial_scan(target, output_file):
    if os.path.isfile(target):
        file_type = input("Is the file a list of IPs or domains? (ips/domains): ").strip().lower()
        if file_type == 'ips':
            perform_nmap_on_file(target)
        elif file_type == 'domains':
            choice = input("Do you want to perform nslookup or check for additional subdomains? (nslookup/subdomains): ").strip().lower()
            if choice == 'nslookup':
                perform_nslookup_on_file(target)
            elif choice == 'subdomains':
                sublist3r_scan_file(target, output_file)
        else:
            print("Invalid input. Please specify 'ips' or 'domains'.")
            sys.exit(1)
    else:
        print(f"Starting initial scan for {target}...")
        if validate_ip(target) or '/' in target:  # Assume it's an IP range if it contains '/'
            nslookup_result = nslookup(target)
            with open(output_file, 'w') as file:
                file.write(f"NSLookup result for {target}: {nslookup_result}\n")
            print(f"NSLookup result for {target}: {nslookup_result}")
        else:  # Assume it's a domain
            sublist3r_scan_and_print(target, output_file)
        print("Initial scan completed.")

def perform_nmap_on_file(file_path):
    output_file = file_path + '.nmap.out'
    nmap_flags = input("Enter nmap flags (e.g., -sP -p 80): ").strip()
    while not all(flag.startswith('-') for flag in nmap_flags.split()):
        print("Invalid flags. Please ensure each flag starts with a '-'")
        nmap_flags = input("Enter nmap flags (e.g., -sP -p 80): ").strip()
    
    nmap_output_choice = input("Do you want to output nmap results to a file? (y/n): ").strip().lower()
    nmap_output_file = None
    nmap_output_format = 'oA'
    if nmap_output_choice == 'y':
        nmap_output_file = input("Enter the output file name: ").strip()
        nmap_output_format = input("Enter the output format (oA, oN, oX) [default: oA]: ").strip().lower()
        if nmap_output_format not in ['oA', 'oN', 'oX']:
            nmap_output_format = 'oA'
    
    process_file(file_path, 'ips', False, None, True, nmap_flags, nmap_output_file, nmap_output_format, False)

def sublist3r_scan_file(file_path, output_file):
    with open(file_path, 'r') as file:
        domains = file.readlines()
    for domain in domains:
        sublist3r_scan_and_print(domain.strip(), output_file)
    ask_nslookup_sublist3r_results(output_file)

def ask_nslookup_sublist3r_results(sublist3r_output_file):
    choice = input("Do you want to perform nslookup on the domains found by Sublist3r? (y/n): ").strip().lower()
    if choice == 'y':
        perform_nslookup_on_file(sublist3r_output_file)

def perform_nslookup_on_file(file_path):
    output_file = file_path + '.nslookup.out'
    with open(file_path, 'r') as file:
        lines = file.readlines()
    with open(output_file, 'w') as out_file:
        for line in lines:
            domain = line.strip()
            print(f"Performing nslookup for {domain}...")
            try:
                ip = nslookup(domain)
                out_file.write(f"{domain} -> {ip}\n")
                print(f"Result: {domain} -> {ip}")
            except Exception as e:
                print(f"Error performing nslookup for {domain}: {e}")
    print(f"NSLookup results written to {output_file}")

def sublist3r_scan_and_print(domain, output_file):
    results = sublist3r_scan(domain)
    with open(output_file, 'a') as out_file:
        for result in results:
            print(result)
            out_file.write(result + '\n')
    print(f"Sublist3r results written to {output_file}")

def main():
    print("Starting EdgeFinder initialization...")
    check_dependencies()
    
    print_ascii_art()
    
    target = input("Enter an IP address, range, domain name, or file path: ").strip()
    output_file = input("Enter the name of your project: ").strip() + '.out'
    
    initial_scan(target, output_file)
    
    args = parse_args()
    
    if not args.file or not args.type:
        print("File and type are required parameters. Use -h for help.")
        sys.exit(1)
    
    if args.type == 'domains' and args.nslookup and not args.output:
        print("Output file name is required when using nslookup.")
        sys.exit(1)
    
    if args.nmap and not args.ip_file:
        print("IP file is required when using nmap.")
        sys.exit(1)
    
    process_file(args.file, args.type, args.nslookup, args.output, args.nmap, args.ip_file, args.quiet)

if __name__ == "__main__":
    main()
