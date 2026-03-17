# Python3 Script: Port Scanner using Nmap and Python
# Author: Tejas Padia (Educational Use Only)
# This tool scans open ports on a target IP using Nmap commands.

import nmap              # Python wrapper for Nmap
import ipaddress         # To validate IP addresses
import shutil            # To check if Nmap is installed
import sys               # To exit program on errors

# Step 1: Display welcome banner
def display_welcome():
    print("""
***********************************************************************
                        🔍 Nmap Scanner Project 🔍
       A simple Python tool for port scanning using Nmap engine.
***********************************************************************
""")

# Step 2: Get and validate the target IP address
def get_ip_address():
    while True:
        ip = input("Please Enter The IP Address To Scan: ")
        try:
            # Validate input format using ipaddress module
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            print("❌ Invalid IP Address. Please Try Again.")

# Step 3: Ask the user to choose scan type
def get_scan_type():
    print('''\nPlease Choose a scan type:
          1. TCP SYN Scan (Fast & Reliable)
          2. UDP Scan (Slower, Less Reliable)
          3. Comprehensive Scan (TCP + UDP + OS Detection, Slower)''')
    return input("Choose (1, 2, or 3): ")

# Step 4: Perform the Nmap scan based on user input
def perform_scan(ip_addr, scan_type):
    # Check if Nmap is installed on the system
    if not shutil.which("nmap"):
        print("❌ Error: Nmap is not installed. Please install it to use this script.")
        sys.exit(1)

    # Initialize the Nmap scanner
    sc = nmap.PortScanner()

    # Define available scan types with their arguments and protocols
    scan_option = {
        '1': ['-sS -sV', 'tcp'],                              # TCP SYN scan + service version
        '2': ['-sU -sV', 'udp'],                              # UDP scan + service version
        '3': ['-sS -sV -p 1-1000 -O -sC', 'tcp,udp'],         # Full scan (limited ports) + OS detection + default scripts
    }

    # If comprehensive scan selected, warn the user
    if scan_type == '3':
        confirm = input("⚠️ Comprehensive scan may take several minutes. Continue? (y/n): ").lower()
        if confirm != 'y':
            print("🚫 Scan cancelled by user.")
            return

    # Handle invalid scan type
    if scan_type not in scan_option:
        print("❌ Invalid scan type. Please choose a valid option.")
        return

    # Print Nmap version
    print("📦 Nmap Version:", sc.nmap_version())
    print("⏳ Scanning in progress...")

    try:
        # Perform the scan with a timeout to avoid long freeze (default 60 seconds)
        sc.scan(ip_addr, arguments=scan_option[scan_type][0], timeout=60)

        # Check if host responded
        if ip_addr in sc.all_hosts():
            print("\n✅ Host is up. Scan Results:")

            # Handle one or more protocols (tcp, udp)
            protocols = scan_option[scan_type][1].split(',')

            for proto in protocols:
                # Check if protocol is in result
                if proto in sc[ip_addr].all_protocols():
                    print(f"\n🔹 Protocol: {proto.upper()}")
                    print(f"{'Port':<10}{'Service':<20}{'State':<10}")
                    print("-" * 40)
                    # Loop through all ports for this protocol
                    for port, info in sc[ip_addr][proto].items():
                        service = info.get('name', 'unknown')
                        state = info.get('state', 'unknown')
                        print(f"{port:<10}{service:<20}{state:<10}")
                else:
                    print(f"⚠️ No open ports found for {proto.upper()}.")

        else:
            print("⚠️ Host is down or not responding.")

    except Exception as e:
        print(f"❌ An error occurred: {e}")

# Step 5: Main loop to allow repeated scans
def main():
    display_welcome()
    while True:
        ip_addr = get_ip_address()
        scan_type = get_scan_type()
        perform_scan(ip_addr, scan_type)

        again = input("\n🔁 Do you want to scan another IP Address? (y/n): ").lower()
        if again != 'y':
            print("👋 Exiting the scanner. Goodbye!")
            break

# Step 6: Script entry point
if __name__ == "__main__":
    main()
