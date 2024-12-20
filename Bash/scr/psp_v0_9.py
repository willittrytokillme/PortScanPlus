#!/usr/bin/env python3

import sys
import subprocess
import importlib
import os
import asyncio
import concurrent.futures
import socket
from ipaddress import ip_network
import multiprocessing
from typing import List, Dict

# Check if script is run with sudo
if os.geteuid() != 0:
   print("This script requires root privileges. Please run it with sudo.")
   sys.exit(1)

def install_nmap():
   try:
       subprocess.check_call(["apt", "update"])
       subprocess.check_call(["apt", "install", "-y", "python3-nmap"])
       print("python3-nmap has been installed")
   except subprocess.CalledProcessError as e:
       print(f"Error installing python3-nmap: {e}")
       sys.exit(1)

# Try to import nmap, install if not found
try:
   import nmap
except ImportError:
   print("python3-nmap is not installed. Installing...")
   install_nmap()
   try:
       import nmap
   except ImportError:
       print("Error: The 'python3-nmap' module could not be imported.")
       print("Please check your system and try again.")
       sys.exit(1)

def display_banner():
   banner = """
   ███████████                      █████     █████████                                          
   ░███░░░░░███                    ░░███     ███░░░░░███                                   ███    
   ░███    ░███  ██████  ████████  ░███████ ░███    ░░░   ██████   ██████   ████████      ░███    
   ░██████████  ███░░███░░███░░███ ░███░░███░░█████████  ███░░███ ░░░░░███ ░░███░░███  ███████████
   ░███░░░░░░  ░███ ░███ ░███ ░░░  ░███ ░███ ░░░░░░░░███░███ ░░░   ███████  ░███ ░███ ░░░░░███░░░
   ░███        ░███ ░███ ░███      ░███ ░███ ███    ░███░███  ███ ███░░███  ░███ ░███     ░███    
   █████       ░░██████  █████     ████ █████░░█████████ ░░██████ ░░████████ ████ █████    ░░░    
   ░░░░░         ░░░░░░  ░░░░░     ░░░░ ░░░░░  ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░            
   """
   print("Welcome to PortScanPLUS ")
   print("-----------------------------------------")
   print(banner)

def load_extended_tools() -> Dict[int, List[str]]:
    """
    Load the extended tools list from PortscannerToolliste.txt
    Returns a dictionary mapping ports to lists of tools
    """
    tools = {}
    try:
        with open('PortscannerToolliste.txt', 'r') as file:
            exec(file.read(), globals())
        if 'get_extended_tools' in globals():
            # Create a dictionary of all tools for all ports
            for port in range(1, 65536):
                tools[port] = get_extended_tools(port)
        else:
            print("Error: get_extended_tools function not found in PortscannerToolliste.txt")
    except FileNotFoundError:
        print("Error: PortscannerToolliste.txt not found. Using default tools.")
    except Exception as e:
        print(f"Error loading extended tools: {e}")
    return tools

# Load the extended tools at the start of the script
EXTENDED_TOOLS = load_extended_tools()

def scan_network_nmap(network):
   try:
       nm = nmap.PortScanner()
       nm.scan(hosts=network, arguments='-sn')
       return nm.all_hosts()
   except nmap.PortScannerError as e:
       print(f"Nmap scanning error: {e}")
   except Exception as e:
       print(f"An unexpected error occurred during Nmap scanning: {e}")
   return []

def scan_host(ip):
   try:
       socket.create_connection((str(ip), 80), timeout=0.5)
       print(f"Host {ip} is up")
       return str(ip)
   except (socket.timeout, ConnectionRefusedError):
       return None

def scan_network_manual(network):
   try:
       net = ip_network(network)
       with concurrent.futures.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2) as executor:
           results = list(executor.map(scan_host, net.hosts()))
       return [ip for ip in results if ip is not None]
   except Exception as e:
       print(f"An error occurred during manual network scanning: {e}")
       return []

async def scan_port(ip, port):
   try:
       _, writer = await asyncio.open_connection(ip, port)
       writer.close()
       await writer.wait_closed()
       return port
   except:
       return None

async def scan_ports(ip):
   tasks = [scan_port(ip, port) for port in range(1, 1025)]
   results = await asyncio.gather(*tasks)
   return [port for port in results if port is not None]

def choose_from_list(options, prompt, allow_back=True):
   while True:
       print(prompt)
       for i, option in enumerate(options, 1):
           print(f"{i}. {option}")
       if allow_back:
           print("0. Go back")
       try:
           choice = int(input("Enter your choice (number): "))
           if allow_back and choice == 0:
               return None
           if 1 <= choice <= len(options):
               return options[choice - 1]
           else:
               print("Invalid choice. Please try again.")
       except ValueError:
           print("Please enter a valid number.")

def get_tools_for_port(port: int) -> List[str]:
    """
    Get the list of tools for a specific port
    """
    default_tools = [
        f"nmap -p{port} -sV -sC TARGET",
        f"amap -d TARGET {port}",
        f"nc -vv -z TARGET {port}",
        f"telnet TARGET {port}"
    ]
    return EXTENDED_TOOLS.get(port, default_tools)

def launch_tool(tool, target_ip, port):
   tool = tool.replace('TARGET', target_ip).replace('PORT', str(port))
   try:
       subprocess.Popen(['x-terminal-emulator', '-e', 'bash', '-c', f"{tool}; exec bash"])
       print(f"Launched: {tool}")
   except Exception as e:
       print(f"Error launching tool: {e}")

async def main():
    display_banner()
    while True:
        network = input("Enter the network to scan (e.g., 192.168.1.0/24): ")

        print("Attempting to scan network using Nmap...")
        hosts = scan_network_nmap(network)

        if not hosts:
            print("Nmap scanning failed. Falling back to manual scanning method...")
            hosts = scan_network_manual(network)

        if not hosts:
            print("No hosts found or error occurred during scanning.")
            continue

        while True:
            print("\nActive hosts:")
            target_ip = choose_from_list(hosts, "Choose an IP to scan for open ports:")
            if target_ip is None:
                break  # Go back to network input

            print(f"\nScanning ports for {target_ip}...")
            open_ports = await scan_ports(target_ip)

            if open_ports:
                while True:
                    print(f"Open ports on {target_ip}:")
                    chosen_port = choose_from_list(open_ports, "Choose a port for further analysis:")
                    if chosen_port is None:
                        break  # Go back to IP selection
                    print(f"\nYou selected port {chosen_port} on {target_ip}")
                    tools = get_tools_for_port(chosen_port)
                    chosen_tool = choose_from_list(tools, f"Choose a tool to use for port {chosen_port}:")
                    if chosen_tool is None:
                        continue  # Go back to port selection
                    launch_tool(chosen_tool, target_ip, chosen_port)
                    input("Press Enter to continue...")
            else:
                print(f"No open ports found on {target_ip}")
                input("Press Enter to continue...")

if __name__ == "__main__":
    asyncio.run(main())