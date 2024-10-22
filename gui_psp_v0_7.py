import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import subprocess
from ipaddress import ip_network
import socket
import threading
import importlib
import concurrent.futures
from typing import List, Dict
import os
from PIL import Image, ImageTk

def install_and_import(package):
    try:
        return importlib.import_module(package)
    except ImportError:
        try:
            subprocess.check_call(["sudo", "apt", "install", "-y", f"python3-{package}"])
            importlib.invalidate_caches()
            return importlib.import_module(package)
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", f"Failed to install {package}. Please install it manually.")
            sys.exit(1)

# Try to import nmap, install if not present
nmap = install_and_import('nmap')

def load_extended_tools() -> Dict[int, List[str]]:
    """
    Load the extended tools list from PortscannerToolliste.txt
    Returns a dictionary mapping ports to lists of tools
    """
    tools = {}
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, 'PortscannerToolliste.txt')
   
    try:
        with open(file_path, 'r') as file:
            exec(file.read(), globals())
        if 'get_extended_tools' in globals():
            # Create a dictionary of all tools for all ports
            for port in range(1, 65536):
                tools[port] = get_extended_tools(port)
        else:
            print("Error: get_extended_tools function not found in PortscannerToolliste.txt")
    except FileNotFoundError:
        print(f"Error: PortscannerToolliste.txt not found in {script_dir}. Using default tools.")
    except Exception as e:
        print(f"Error loading extended tools: {e}")
    return tools

# Load the extended tools at the start of the script
EXTENDED_TOOLS = load_extended_tools()

class PortScanPlusGUI:
    def __init__(self, master):
        self.master = master
        master.title("PortScanPLUS")
       
        # Calculate window size and position
        screen_width, screen_height = master.winfo_screenwidth(), master.winfo_screenheight()
        window_width, window_height = int(screen_width * 0.8), int(screen_height * 0.8)
        x, y = (screen_width - window_width) // 2, (screen_height - window_height) // 2
       
        master.geometry(f"{window_width}x{window_height}+{x}+{y}")
        master.resizable(True, True)

        # Set updated color scheme
        self.bg_color = 'dimgrey'
        self.fg_color = 'lawngreen'
        self.highlight_color = 'gold'
        master.configure(bg=self.bg_color)

        # Add icon
        self.add_icon()

        self.create_widgets()

    def add_icon(self):
        try:
            # Assuming the image file is named 'portscan_icon.png' and is in the same directory as the script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(script_dir, 'portscan_icon.png')
           
            # Open the image and resize it to 100x100 pixels
            img = Image.open(icon_path)
            img = img.resize((100, 100), Image.LANCZOS)
           
            self.icon = ImageTk.PhotoImage(img)
           
            # Create a label to hold the image and place it in the upper left corner
            icon_label = tk.Label(self.master, image=self.icon, bg=self.bg_color)
            icon_label.image = self.icon  # Keep a reference to prevent garbage collection
            icon_label.place(x=10, y=10)  # Position in the upper left corner
        except Exception as e:
            print(f"Error loading icon: {e}")

    def create_widgets(self):
        # Network Input
        tk.Label(self.master, text="Network to scan (e.g., 192.168.1.0/24):", bg=self.bg_color, fg=self.fg_color).pack(pady=(120, 5))
        self.network_entry = tk.Entry(self.master, width=50, bg=self.bg_color, fg=self.fg_color, insertbackground=self.fg_color)
        self.network_entry.pack(pady=5)

        # Scan Network Button
        self.scan_button = tk.Button(self.master, text="Scan Network", command=self.scan_network, bg=self.bg_color, fg=self.fg_color)
        self.scan_button.pack(pady=10)

        # Results Area with custom tags
        self.results_text = scrolledtext.ScrolledText(self.master, height=20, bg=self.bg_color, fg=self.fg_color)
        self.results_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.results_text.tag_configure('highlight', foreground=self.highlight_color)

        # Host Selection
        self.host_var = tk.StringVar()
        self.host_dropdown = ttk.Combobox(self.master, textvariable=self.host_var, state="disabled")
        self.host_dropdown.pack(pady=5)

        # Choose Host Button
        self.choose_host_button = tk.Button(self.master, text="Choose Host", command=self.choose_host, bg=self.bg_color, fg=self.fg_color)
        self.choose_host_button.pack(pady=5)

        # Port Scan Button
        self.port_scan_button = tk.Button(self.master, text="Scan Ports", command=self.scan_ports, bg=self.bg_color, fg=self.fg_color)
        self.port_scan_button.pack(pady=5)

        # Port Selection
        self.port_var = tk.StringVar()
        self.port_dropdown = ttk.Combobox(self.master, textvariable=self.port_var, state="disabled")
        self.port_dropdown.pack(pady=5)

        # Choose Port Button
        self.choose_port_button = tk.Button(self.master, text="Choose Port", command=self.choose_port, bg=self.bg_color, fg=self.fg_color)
        self.choose_port_button.pack(pady=5)

        # Tool Selection
        self.tool_var = tk.StringVar()
        self.tool_dropdown = ttk.Combobox(self.master, textvariable=self.tool_var, state="disabled")
        self.tool_dropdown.pack(pady=5)

        # Launch Tool Button
        self.launch_button = tk.Button(self.master, text="Launch Tool", command=self.launch_tool, bg=self.bg_color, fg=self.fg_color)
        self.launch_button.pack(pady=10)

        # Configure the style for dropdowns
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure('TCombobox', fieldbackground=self.bg_color, background=self.bg_color, foreground=self.fg_color)

    def scan_network(self):
        network = self.network_entry.get()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Scanning network: {network}\n")
        self.scan_button.config(state="disabled")
       
        threading.Thread(target=self._scan_network_thread, args=(network,)).start()

    def _scan_network_thread(self, network):
        hosts = self.scan_network_nmap(network) or self.scan_network_manual(network)
        self.master.after(0, self._update_gui_after_network_scan, hosts)

    def _update_gui_after_network_scan(self, hosts):
        if hosts:
            self.results_text.insert(tk.END, "Active hosts:\n")
            for host in hosts:
                self.results_text.insert(tk.END, f"{host}\n", 'highlight')
            self.host_dropdown['values'] = hosts
            self.host_dropdown['state'] = 'readonly'
        else:
            self.results_text.insert(tk.END, "No hosts found or error occurred during scanning.\n")
        self.scan_button.config(state="normal")

    def scan_network_nmap(self, network):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments='-sn')
            return nm.all_hosts()
        except Exception as e:
            self.results_text.insert(tk.END, f"An error occurred during Nmap scanning: {e}\n")
        return []

    def scan_network_manual(self, network):
        try:
            net = ip_network(network)
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(self._check_host, str(ip)) for ip in net.hosts()]
                active_hosts = [f.result() for f in concurrent.futures.as_completed(futures) if f.result()]
            return active_hosts
        except Exception as e:
            self.master.after(0, self.results_text.insert, tk.END, f"An error occurred during manual network scanning: {e}\n")
        return []

    def _check_host(self, ip):
        try:
            socket.create_connection((ip, 80), timeout=1)
            self.master.after(0, self.results_text.insert, tk.END, f"Host {ip} is up\n", 'highlight')
            return ip
        except (socket.timeout, ConnectionRefusedError):
            return None

    def choose_host(self):
        selected_host = self.host_var.get()
        if selected_host:
            self.results_text.insert(tk.END, f"Selected host: ", 'highlight')
            self.results_text.insert(tk.END, f"{selected_host}\n", 'highlight')
        else:
            messagebox.showwarning("Warning", "Please select a host from the dropdown.")

    def scan_ports(self):
        ip = self.host_var.get()
        if not ip:
            messagebox.showwarning("Warning", "Please select a host first.")
            return
        self.results_text.insert(tk.END, f"\nScanning ports for {ip}...\n")
        self.port_scan_button.config(state="disabled")
       
        threading.Thread(target=self._scan_ports_thread, args=(ip,)).start()

    def _scan_ports_thread(self, ip):
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self._check_port, ip, port) for port in range(1, 1025)]
            open_ports = [f.result() for f in concurrent.futures.as_completed(futures) if f.result()]
       
        self.master.after(0, self._update_gui_after_port_scan, open_ports)

    def _check_port(self, ip, port):
        try:
            with socket.create_connection((ip, port), timeout=1):
                self.master.after(0, self.results_text.insert, tk.END, f"Port {port} is open\n", 'highlight')
                return str(port)
        except (socket.timeout, ConnectionRefusedError):
            return None

    def _update_gui_after_port_scan(self, open_ports):
        if open_ports:
            self.port_dropdown['values'] = open_ports
            self.port_dropdown['state'] = 'readonly'
        else:
            self.results_text.insert(tk.END, f"No open ports found on {self.host_var.get()}\n")
        self.port_scan_button.config(state="normal")

    def choose_port(self):
        selected_port = self.port_var.get()
        if selected_port:
            self.results_text.insert(tk.END, f"Selected port: ", 'highlight')
            self.results_text.insert(tk.END, f"{selected_port}\n", 'highlight')
            self.update_tools()
            self.tool_dropdown['state'] = 'readonly'
        else:
            messagebox.showwarning("Warning", "Please select a port from the dropdown.")

    def update_tools(self):
        port = int(self.port_var.get())
        tools = self.get_tools_for_port(port)
        self.tool_dropdown['values'] = tools
        if tools:
            self.tool_var.set(tools[0])

    def get_tools_for_port(self, port: int) -> List[str]:
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

    def launch_tool(self):
        tool = self.tool_var.get()
        target_ip = self.host_var.get()
        port = self.port_var.get()
       
        if not tool or not target_ip or not port:
            messagebox.showwarning("Warning", "Please complete all previous steps before launching a tool.")
            return

        tool = tool.replace('TARGET', target_ip).replace('PORT', port)
        try:
            subprocess.Popen(['x-terminal-emulator', '-e', 'bash', '-c', f"{tool}; exec bash"])
            self.results_text.insert(tk.END, f"Launched: {tool}\n")
        except Exception as e:
            self.results_text.insert(tk.END, f"Error launching tool: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanPlusGUI(root)
    root.mainloop()