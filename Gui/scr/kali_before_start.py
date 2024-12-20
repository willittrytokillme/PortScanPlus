#!/usr/bin/env python3
import subprocess
import sys
import os

def install_nmap_dependencies():
    """
    Standalone script to install nmap and python-nmap
    """
    if os.geteuid() != 0:
        print("This script needs to be run as root.")
        print("Please run with: sudo python3 install_dependencies.py")
        sys.exit(1)

    try:
        # Update package list
        print("Updating package list...")
        subprocess.check_call(['apt', 'update'])
        
        # Install nmap
        print("Installing nmap...")
        subprocess.check_call(['apt', 'install', '-y', 'nmap'])
        
        # Install python-nmap
        print("Installing python-nmap...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--break-system-packages', 'python-nmap'])
        
        print("\nDependencies installed successfully!")
        print("You can now run the main program with: sudo python3 gui_psp2_0.py")
        
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install_nmap_dependencies()
