import argparse
import logging
import subprocess
import nmap
import ipaddress
from datetime import datetime

# Setting up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Function to run Nmap scan
def run_nmap_scan(target_ip):
    logger.info(f"Running Nmap Scan on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-1024')  # Adjust port range as needed
    logger.info(f"Nmap Scan Completed for {target_ip}.")
    return nm

# Function to run Nikto scan for web vulnerabilities
def run_nikto_scan(target_ip):
    logger.info(f"Running Nikto Web Vulnerability Scan on {target_ip}...")
    command = f"nikto -h http://{target_ip}"
    subprocess.run(command, shell=True)
    logger.info(f"Nikto Scan Completed for {target_ip}.")

# Function to run Wapiti for web application vulnerabilities
def run_wapiti_scan(target_ip):
    logger.info(f"Running Wapiti Web Vulnerability Scan on {target_ip}...")
    command = f"wapiti -u http://{target_ip} -o {target_ip}_wapiti_report"
    subprocess.run(command, shell=True)
    logger.info(f"Wapiti Scan Completed for {target_ip}.")

# Function to run Metasploit for basic exploit checks
def run_metasploit(target_ip):
    logger.info(f"Starting Metasploit for Exploit Check on {target_ip}...")
    msfconsole_command = f"msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {target_ip}; run; exit'"
    subprocess.run(msfconsole_command, shell=True)
    logger.info(f"Metasploit Check Completed for {target_ip}.")

# Function to perform service enumeration using Nmap
def enumerate_services(nmap_output, target_ip):
    logger.info(f"Enumerating Services for {target_ip}...")
    report = []
    for host in nmap_output.all_hosts():
        if host == target_ip:
            for proto in nmap_output[host].all_protocols():
                lport = nmap_output[host][proto].keys()
                for port in lport:
                    state = nmap_output[host][proto][port]['state']
                    report.append(f"Host: {host} | Port: {port} | State: {state}")
    logger.info(f"Service Enumeration Completed for {target_ip}.")
    return report

# Function to check for open ports on a target
def check_open_ports(target_ip):
    logger.info(f"Checking for Open Ports on {target_ip}...")
    nmap_output = run_nmap_scan(target_ip)
    service_report = enumerate_services(nmap_output, target_ip)
    return service_report

# Function to check for vulnerabilities and exploits
def check_vulnerabilities(target_ip):
    logger.info(f"Checking for Vulnerabilities on {target_ip}...")
    run_nikto_scan(target_ip)
    run_wapiti_scan(target_ip)
    run_metasploit(target_ip)

# Function to perform a penetration test on the target
def penetration_test(target_ip):
    logger.info(f"Starting Penetration Test for {target_ip}...")
    service_report = check_open_ports(target_ip)
    check_vulnerabilities(target_ip)
    logger.info(f"Penetration Test Completed for {target_ip}.")
    return service_report

# Function to generate a report for a target
def generate_report(target_ip, service_report):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"penetration_test_report_{target_ip}_{timestamp}.txt"
    with open(filename, 'w') as report_file:
        report_file.write(f"Penetration Test Report for {target_ip}\n")
        report_file.write(f"Date: {timestamp}\n\n")
        report_file.write("[*] Open Ports and Services:\n")
        for line in service_report:
            report_file.write(f"{line}\n")
        report_file.write("\n[*] Nikto, Wapiti, and Metasploit results saved separately.\n")
    logger.info(f"Report generated: {filename}")

# Function to scan multiple targets
def scan_targets(ip_list):
    for target_ip in ip_list:
        logger.info(f"Starting tests for IP: {target_ip}")
        try:
            service_report = penetration_test(target_ip)
            generate_report(target_ip, service_report)
        except Exception as e:
            logger.error(f"Error testing IP {target_ip}: {e}")

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Run penetration tests on a list of IPs.")
    parser.add_argument('--file', required=True, help="Path to the file containing IP addresses.")
    return parser.parse_args()

# Function to read IPs from a file
def read_ips_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        return ips
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        exit(1)
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        exit(1)

# Main function
def main():
    args = parse_arguments()
    ip_file = args.file
    ips = read_ips_from_file(ip_file)
    scan_targets(ips)

if __name__ == "__main__":
    main()

