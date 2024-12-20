import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import subprocess
from ipaddress import ip_network
import socket
import threading
import importlib
import concurrent.futures
from typing import List, Dict, Set, Optional
import os
from PIL import Image, ImageTk
from functools import lru_cache
import asyncio
import queue
import time

# Import extended tools from the tools file
def load_extended_tools():
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        tools_file = os.path.join(script_dir, 'PortscannerToolliste.txt')
        
        # Create a temporary module name
        module_name = 'port_tools_temp'
        
        # First, inject the necessary imports into the module
        module = type(sys)(module_name)
        module.__dict__['List'] = List  # Add List type from typing
        
        with open(tools_file) as f:
            code = compile(f.read(), tools_file, 'exec')
            
        # Execute the code in the module's namespace
        exec(code, module.__dict__)
        
        # Get the tools dictionary
        if hasattr(module, 'get_extended_tools'):
            return module.get_extended_tools
        else:
            print("Error: get_extended_tools function not found in tools file")
            return None
    except Exception as e:
        print(f"Error loading extended tools: {e}")
        return None

# Global variable for extended tools
EXTENDED_TOOLS_FUNCTION = load_extended_tools()

try:
    import nmap
    NMAP_AVAILABLE = True
    print("Successfully imported nmap")
except ImportError as e:
    NMAP_AVAILABLE = False
    print(f"Failed to import nmap: {e}")
    print("Please ensure python-nmap is installed in your virtual environment")

class ModernButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            relief=tk.RAISED,
            borderwidth=1,
            padx=15,
            pady=8,
            font=('Helvetica', 10),
            cursor='hand2'
        )
        self.bind('<Enter>', self._on_hover)
        self.bind('<Leave>', self._on_leave)

    def _on_hover(self, event):
        self.configure(relief=tk.SUNKEN)

    def _on_leave(self, event):
        self.configure(relief=tk.RAISED)

class ModernCombobox(ttk.Combobox):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            width=30,
            height=25,
            font=('Helvetica', 10)
        )
        
class PortScanPlusGUI:
    def __init__(self, master):
        self.master = master
        master.title("PortScanPLUS")
   
        # Print debug info about nmap availability
        if NMAP_AVAILABLE:
            print("Nmap is available for use")
        else:
            print("Nmap is not available, will use manual scanning")
   
        # Set window properties
        self._configure_window()
   
        # Initialize styling
        self._initialize_styles()
   
        # Create the main container with padding
        self.main_container = ttk.Frame(master, padding="10")
        self.main_container.pack(fill=tk.BOTH, expand=True)
   
        # Initialize button references
        self.scan_button = None
        self.scan_ports_button = None
        self.choose_host_button = None
        self.choose_port_button = None
        self.start_tools_button = None
   
        # Create all widgets
        self._create_widgets()
   
        # Initialize message queue for updates
        self.message_queue = queue.Queue()
        self._start_ui_updater()

    def scan_network(self):
        """Start network scanning process"""
        network = self.network_entry.get()
        if not network:
            messagebox.showwarning("Warning", "Please enter a network address.")
            return
       
        self.scan_button.config(state="disabled")
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Scanning network {network}...\n")
       
        threading.Thread(target=self._scan_network_thread, args=(network,), daemon=True).start()

    def _scan_network_thread(self, network):
        print("Starting network scan...")
        hosts = None
        if NMAP_AVAILABLE:
            print("Attempting nmap scan...")
            hosts = self.scan_network_nmap(network)
        if hosts is None:
            print("Using manual scan method...")
            hosts = self.scan_network_manual(network)
        print(f"Scan complete. Found {len(hosts) if hosts else 0} hosts")
        self.master.after(0, self._update_gui_after_network_scan, hosts)

    def scan_network_manual(self, network):
        try:
            net = ip_network(network)
            active_hosts = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(self._check_host, str(ip)) for ip in net.hosts()]
                for future in concurrent.futures.as_completed(futures):
                    if result := future.result():
                        active_hosts.append(result)
            return active_hosts
        except Exception as e:
            self.message_queue.put(("Error during manual network scanning: " + str(e) + "\n", 'error'))
            return []

    def _check_host(self, ip):
        """Check if a host is active with auto-scrolling output"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, 80))
                self.message_queue.put((f"Host {ip} is up\n", 'success'))
                return ip
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _create_widgets(self):
        """Create all GUI widgets"""
        self._create_header_section()
        self._create_network_section()
        self._create_control_section()
        self._create_results_section()
        # Remove the duplicate port scan button creation

    def _start_ui_updater(self):
        """Initialize and start the UI update loop with debug printing"""
        def update_loop():
            try:
                while True:
                    try:
                        message = self.message_queue.get_nowait()
                        print(f"Debug: Processing message: {message}")  # Debug print
                        
                        if isinstance(message, tuple):
                            text, tags = message
                            self.results_text.insert(tk.END, text, tags)
                        else:
                            self.results_text.insert(tk.END, str(message))
                        
                        # Force update
                        self.results_text.see(tk.END)
                        self.results_text.update()
                        
                    except queue.Empty:
                        break
                    
                # Schedule next update
                self.master.after(100, update_loop)
                
            except tk.TclError:
                print("Debug: Window closed")  # Debug print
                return
        
        self.master.after(100, update_loop)

    def add_message(self, message, tag=None):
        """Add a message to the results text with auto-scroll"""
        self.results_text.insert(tk.END, message, tag if tag else '')
        self.results_text.see(tk.END)
        self.results_text.update_idletasks()

    def _configure_window(self):
            """Configure the main window properties"""
            # Calculate window size and position
            screen_width = self.master.winfo_screenwidth()
            screen_height = self.master.winfo_screenheight()
            window_width = int(screen_width * 0.8)
            window_height = int(screen_height * 0.8)
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2
       
            self.master.geometry(f"{window_width}x{window_height}+{x}+{y}")
            self.master.resizable(True, True)
            self.master.configure(bg='#2b2b2b')  # Dark background

    def _initialize_styles(self):
        """Initialize ttk styles for the application"""
        self.style = ttk.Style()
        self.style.configure('Header.TLabel',
            font=('Helvetica', 12, 'bold'),
            foreground='#e0e0e0',
            background='#2b2b2b',
            padding=10
        )
       
        self.style.configure('Modern.TFrame',
            background='#2b2b2b',
            borderwidth=1,
            relief='flat'
        )
       
        self.style.configure('Modern.TButton',
            font=('Helvetica', 10),
            padding=8,
            background='#404040',
            foreground='#e0e0e0'
        )
       
        self.style.configure('Modern.TCombobox',
            background='#404040',
            fieldbackground='#404040',
            foreground='#e0e0e0',
            arrowcolor='#e0e0e0'
        )

    def _create_widgets(self):
        """Create all GUI widgets"""
        self._create_header_section()
        self._create_network_section()
        self._create_control_section()
        self._create_results_section()

    def _create_header_section(self):
        """Create the header section of the GUI"""
        header_frame = ttk.Frame(self.main_container, style='Modern.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 10))
       
        # Add logo/icon
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(script_dir, 'portscan_icon.png')
            img = Image.open(icon_path)
            img = img.resize((50, 50), Image.LANCZOS)
            self.icon = ImageTk.PhotoImage(img)
            icon_label = ttk.Label(header_frame, image=self.icon, background='#2b2b2b')
            icon_label.pack(side=tk.LEFT, padx=10)
        except Exception:
            pass
       
        # Add title
        title_label = ttk.Label(
            header_frame,
            text="PortScanPLUS",
            style='Header.TLabel'
        )
        title_label.pack(side=tk.LEFT, padx=10)

    def _create_network_section(self):
        """Create the network input section with added deep scan button"""
        network_frame = ttk.Frame(self.main_container, style='Modern.TFrame')
        network_frame.pack(fill=tk.X, pady=10)
        
        # Network input row
        input_frame = ttk.Frame(network_frame, style='Modern.TFrame')
        input_frame.pack(fill=tk.X)
        
        ttk.Label(
            input_frame,
            text="Network:",
            style='Header.TLabel'
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.network_entry = ttk.Entry(
            input_frame,
            font=('Helvetica', 10),
            width=40
        )
        self.network_entry.pack(side=tk.LEFT, padx=5)
        self.network_entry.insert(0, "192.168.1.0/24")
        
        self.scan_button = ModernButton(
            input_frame,
            text="Quick Scan",
            command=self.scan_network,
            bg='#404040',
            fg='#e0e0e0'
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)

        # Add Deep Scan button
        self.deep_scan_button = ModernButton(
            input_frame,
            text="Deep Scan",
            command=self.deep_scan_host,
            bg='#404040',
            fg='#e0e0e0'
        )
        self.deep_scan_button.pack(side=tk.LEFT, padx=5)
        self.deep_scan_button.config(state="disabled")  # Initially disabled
    
    def _create_control_section(self):
        """Create the control section with host, port and tool controls"""
        control_frame = ttk.Frame(self.main_container, style='Modern.TFrame')
        control_frame.pack(fill=tk.X, pady=10)
        
        # Create host controls
        self._create_host_controls(control_frame)
        # Create port controls
        self._create_port_controls(control_frame)
        # Create tool controls
        self._create_tool_controls(control_frame)

    def _create_host_controls(self, parent):
        """Create host selection controls"""
        host_frame = ttk.Frame(parent, style='Modern.TFrame')
        host_frame.pack(side=tk.LEFT, expand=True, padx=5)
   
        ttk.Label(
            host_frame,
            text="Host:",
            style='Header.TLabel'
        ).pack(side=tk.LEFT)
   
        self.host_var = tk.StringVar()
        self.host_dropdown = ModernCombobox(
            host_frame,
            textvariable=self.host_var,
            state="disabled"
        )
        self.host_dropdown.pack(side=tk.LEFT, padx=5)
   
        # Add Choose Host button
        self.choose_host_button = ModernButton(
            host_frame,
            text="Choose Host",
            command=self.choose_host,
            bg='#404040',
            fg='#e0e0e0'
        )
        self.choose_host_button.pack(side=tk.LEFT, padx=5)
        self.choose_host_button.config(state="disabled")
        
    def deep_scan_host(self):
        """Perform deep scan on selected host"""
        selected_host = self.host_var.get()
        if not selected_host:
            messagebox.showwarning("Warning", "Please select a host first.")
            return

        self.deep_scan_button.config(state="disabled")
        self.results_text.insert(tk.END, f"\nStarting deep scan of {selected_host}...\n")
        threading.Thread(target=self._deep_scan_thread, args=(selected_host,), daemon=True).start()

    def _deep_scan_thread(self, host):
        """Thread for performing deep scan"""
        try:
            nm = nmap.PortScanner()
            self.message_queue.put((f"\n{'='*60}\n", 'info'))
            self.message_queue.put((f"Performing deep scan of: {host}\n", 'highlight'))
            
            # Perform detailed scan
            nm.scan(host, arguments='-sS -sV -O -A --version-intensity 5')
            
            if host in nm.all_hosts():
                host_data = nm[host]
                
                # OS Detection
                if 'osmatch' in host_data:
                    self.message_queue.put(("\nOperating System Detection:\n", 'highlight'))
                    for osmatch in host_data['osmatch']:
                        self.message_queue.put((
                            f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n", 
                            'success'
                        ))
                        if 'osclass' in osmatch:
                            for osclass in osmatch['osclass']:
                                self.message_queue.put((
                                    f"  Type: {osclass.get('type', 'N/A')}\n"
                                    f"  Vendor: {osclass.get('vendor', 'N/A')}\n"
                                    f"  Family: {osclass.get('osfamily', 'N/A')}\n"
                                    f"  Gen: {osclass.get('osgen', 'N/A')}\n",
                                    'info'
                                ))

                # Port and Service Information
                for proto in nm[host].all_protocols():
                    ports = sorted(nm[host][proto].keys())
                    if ports:
                        self.message_queue.put((f"\nOpen Ports ({proto}):\n", 'highlight'))
                        for port in ports:
                            service = nm[host][proto][port]
                            service_info = []
                            
                            if 'name' in service:
                                service_info.append(f"Service: {service['name']}")
                            if 'product' in service:
                                service_info.append(f"Product: {service['product']}")
                            if 'version' in service:
                                service_info.append(f"Version: {service['version']}")
                            if 'extrainfo' in service:
                                service_info.append(f"Info: {service['extrainfo']}")
                            if 'cpe' in service and service['cpe']:
                                service_info.append(f"CPE: {service['cpe']}")
                                
                            port_info = f"Port {port}: {' | '.join(service_info)}\n"
                            self.message_queue.put((port_info, 'success'))

                # MAC and Vendor Information
                if 'vendor' in host_data:
                    self.message_queue.put(("\nNetwork Interfaces:\n", 'highlight'))
                    for mac, vendor in host_data['vendor'].items():
                        self.message_queue.put((f"MAC: {mac} ({vendor})\n", 'info'))

                # Scripts Output
                if 'scripts' in host_data:
                    self.message_queue.put(("\nScript Results:\n", 'highlight'))
                    for script_name, output in host_data['scripts'].items():
                        self.message_queue.put((f"Script: {script_name}\n", 'info'))
                        self.message_queue.put((f"{output}\n", 'info'))

            self.message_queue.put(("\nDeep scan completed.\n", 'success'))
            
        except Exception as e:
            self.message_queue.put((f"Error during deep scan: {str(e)}\n", 'error'))
        
        finally:
            # Re-enable the deep scan button
            self.master.after(0, lambda: self.deep_scan_button.config(state="normal"))    

    def _create_port_controls(self, parent):
        """Create port selection controls"""
        port_frame = ttk.Frame(parent, style='Modern.TFrame')
        port_frame.pack(side=tk.LEFT, expand=True, padx=5)
   
        ttk.Label(
            port_frame,
            text="Port:",
            style='Header.TLabel'
        ).pack(side=tk.LEFT)
   
        self.port_var = tk.StringVar()
        self.port_dropdown = ModernCombobox(
            port_frame,
            textvariable=self.port_var,
            state="disabled"
        )
        self.port_dropdown.pack(side=tk.LEFT, padx=5)
   
        # Create scan ports button
        self.scan_ports_button = ModernButton(
            port_frame,
            text="Scan Ports",
            command=self.scan_ports,
            bg='#404040',
            fg='#e0e0e0'
        )
        self.scan_ports_button.pack(side=tk.LEFT, padx=5)
        self.scan_ports_button.config(state="disabled")
   
        # Add Choose Port button
        self.choose_port_button = ModernButton(
            port_frame,
            text="Choose Port",
            command=self.choose_port,
            bg='#404040',
            fg='#e0e0e0'
        )
        self.choose_port_button.pack(side=tk.LEFT, padx=5)
        self.choose_port_button.config(state="disabled")

    def _create_tool_controls(self, parent):
        """Create tool selection controls"""
        tool_frame = ttk.Frame(parent, style='Modern.TFrame')
        tool_frame.pack(side=tk.LEFT, expand=True, padx=5)
   
        ttk.Label(
            tool_frame,
            text="Tool:",
            style='Header.TLabel'
        ).pack(side=tk.LEFT)
   
        self.tool_var = tk.StringVar()
        self.tool_dropdown = ModernCombobox(
            tool_frame,
            textvariable=self.tool_var,
            state="disabled"
        )
        self.tool_dropdown.pack(side=tk.LEFT, padx=5)
   
        # Add Start Tools button
        self.start_tools_button = ModernButton(
            tool_frame,
            text="Start Tools",
            command=self.launch_tool,
            bg='#404040',
            fg='#e0e0e0'
        )
        self.start_tools_button.pack(side=tk.LEFT, padx=5)
        self.start_tools_button.config(state="disabled")

    def _create_results_section(self):
        """Create the results section with auto-scrolling text area"""
        results_frame = ttk.Frame(self.main_container, style='Modern.TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(
            results_frame,
            text="Scan Results:",
            style='Header.TLabel'
        ).pack(anchor=tk.W)
        
        # Create text widget with auto-scroll capability
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            bg='#1e1e1e',
            fg='#e0e0e0',
            font=('Consolas', 10),
            insertbackground='#e0e0e0'
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different types of output
        self.results_text.tag_configure('success', foreground='#4CAF50')
        self.results_text.tag_configure('error', foreground='#f44336')
        self.results_text.tag_configure('info', foreground='#2196F3')
        self.results_text.tag_configure('warning', foreground='#FFC107')
        self.results_text.tag_configure('highlight', foreground='#E91E63')
        
        # Enable auto-scrolling
        self.results_text.see(tk.END)
        self.results_text.bind('<KeyRelease>', lambda e: self.results_text.see(tk.END))

    def scan_network_nmap(self, network):
        """Quick network scan for host discovery"""
        if not NMAP_AVAILABLE:
            self.message_queue.put(("Nmap module not found. Falling back to manual scan...\n", 'error'))
            return None
        
        try:
            nm = nmap.PortScanner()
            # Only perform host discovery
            nm.scan(hosts=network, arguments='-sn')
            return nm.all_hosts()
        except Exception as e:
            self.message_queue.put((f"Error during network scan: {str(e)}\n", 'error'))
            return None

    def _scan_network_thread(self, network):
        print("Starting network scan...")
        hosts = None
        if NMAP_AVAILABLE:
            print("Attempting nmap scan...")
            hosts = self.scan_network_nmap(network)
        if hosts is None:
            print("Using manual scan method...")
            hosts = self.scan_network_manual(network)
        print(f"Scan complete. Found {len(hosts) if hosts else 0} hosts")
        self.master.after(0, self._update_gui_after_network_scan, hosts)

    def _update_gui_after_network_scan(self, hosts):
        if hosts:
            final_msg = f"\nScan Completed Successfully\nTotal hosts found: {len(hosts)}\n"
            self.results_text.insert(tk.END, final_msg)
            print(f"Debug: Scan complete - {final_msg}")  # Debug print
            
            self.host_dropdown['values'] = hosts
            self.host_dropdown['state'] = 'readonly'
            self.choose_host_button.config(state="normal")
        else:
            error_msg = "No hosts found or error occurred during scanning.\n"
            self.results_text.insert(tk.END, error_msg)
            print(f"Debug: No hosts found - {error_msg}")  # Debug print
            
        self.scan_button.config(state="normal")
        self.results_text.see(tk.END)
        self.results_text.update()

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
        """Modified choose_host to enable deep scan button"""
        selected_host = self.host_var.get()
        if selected_host:
            self.results_text.insert(tk.END, f"Selected host: ", 'highlight')
            self.results_text.insert(tk.END, f"{selected_host}\n", 'highlight')
            self.scan_ports_button.config(state="normal")
            self.deep_scan_button.config(state="normal")  # Enable deep scan button
        else:
            messagebox.showwarning("Warning", "Please select a host from the dropdown.")

    def scan_ports(self):
        """Start port scanning process"""
        ip = self.host_var.get()
        if not ip:
            messagebox.showwarning("Warning", "Please select a host first.")
            return
   
        self.results_text.insert(tk.END, f"\nScanning ports for {ip}...\n")
   
        # Disable only the scan ports button
        if self.scan_ports_button:
            self.scan_ports_button.config(state="disabled")
   
        # Create a progress variable
        self.scan_progress = 0
        self.total_ports = 1024
   
        threading.Thread(target=self._scan_ports_thread, args=(ip,), daemon=True).start()
    
    def _scan_ports_thread(self, ip):
        try:
            # Common ports to check first
            common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]

            # First scan common ports
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                common_futures = {executor.submit(self._check_port, ip, port): port for port in common_ports}
                for future in concurrent.futures.as_completed(common_futures):
                    if future.result():
                        open_ports.append(str(common_futures[future]))
                    self.scan_progress += 1
               
            # Then scan remaining ports in ranges
            remaining_ports = [p for p in range(1, 1025) if p not in common_ports]
            port_ranges = [remaining_ports[i:i + 50] for i in range(0, len(remaining_ports), 50)]
       
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                for port_range in port_ranges:
                    range_futures = {executor.submit(self._check_port, ip, port): port for port in port_range}
                    for future in concurrent.futures.as_completed(range_futures):
                        if future.result():
                            open_ports.append(str(range_futures[future]))
                        self.scan_progress += 1
       
            # Sort the ports numerically for display
            open_ports.sort(key=int)
            self.master.after(0, self._update_gui_after_port_scan, open_ports)
       
        except Exception as e:
            self.message_queue.put((f"Error during port scan: {str(e)}\n", 'error'))
            self.master.after(0, self._update_gui_after_port_scan, [])

    def _check_port(self, ip, port):
        """Check if a specific port is open with auto-scrolling output"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.message_queue.put((f"Port {port} is open\n", 'highlight'))
                    return True
                return False
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _update_gui_after_port_scan(self, open_ports):
        """Update GUI after port scanning is complete with auto-scrolling"""
        if open_ports:
            self.add_message(f"\nFound {len(open_ports)} open ports\n", 'success')
            self.port_dropdown['values'] = open_ports
            self.port_dropdown['state'] = 'readonly'
            if self.choose_port_button:
                self.choose_port_button.config(state="normal")
        else:
            self.add_message(f"No open ports found on {self.host_var.get()}\n", 'warning')
        
        if self.scan_ports_button:
            self.scan_ports_button.config(state="normal")

    def choose_port(self):
        """Handle port selection"""
        selected_port = self.port_var.get()
        if not selected_port:
            messagebox.showwarning("Warning", "Please select a port from the dropdown.")
            return
       
        self.results_text.insert(tk.END, f"Selected port: ", 'highlight')
        self.results_text.insert(tk.END, f"{selected_port}\n", 'highlight')
   
        # Update tools for the selected port
        self.update_tools()
   
        # Enable tools dropdown and button
        self.tool_dropdown['state'] = 'readonly'
        if self.start_tools_button:
            self.start_tools_button.config(state="normal")
        
    def update_tools(self):
        """Update the tools dropdown based on the selected port"""
        try:
            port = int(self.port_var.get())
            if EXTENDED_TOOLS_FUNCTION:
                tools = EXTENDED_TOOLS_FUNCTION(port)
            else:
                tools = self.get_default_tools(port)
                
            self.tool_dropdown['values'] = tools
            if tools:
                self.tool_var.set(tools[0])
                self.start_tools_button.config(state="normal")
            else:
                self.start_tools_button.config(state="disabled")
                
        except ValueError as e:
            self.results_text.insert(tk.END, f"Error updating tools: {e}\n", 'error')
            self.start_tools_button.config(state="disabled")

    def get_default_tools(self, port: int) -> List[str]:
        """Fallback default tools if the extended tools file fails to load"""
        return [
            f"nmap -p{port} -sV -sC TARGET",
            f"amap -d TARGET {port}",
            f"nc -vv -z TARGET {port}",
            f"telnet TARGET {port}"
        ]

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
        """Launch selected tool with improved terminal handling and error checking"""
        tool = self.tool_var.get()
        target_ip = self.host_var.get()
        port = self.port_var.get()
    
        if not tool or not target_ip or not port:
            messagebox.showwarning("Warning", "Please complete all previous steps before launching a tool.")
            return

        tool = tool.replace('TARGET', target_ip).replace('PORT', port)
    
        # Debug print
        print(f"Attempting to launch tool: {tool}")
    
        try:
        # Check for different terminal emulators
            terminals = [
                # Tuple of (binary_path, launch_command_format)
                ('/usr/bin/gnome-terminal', ['gnome-terminal', '--', 'bash', '-c', '{command}; exec bash']),
                ('/usr/bin/xfce4-terminal', ['xfce4-terminal', '-e', "bash -c '{command}; read -p \"Press Enter to close...\"'"]),
                ('/usr/bin/konsole', ['konsole', '-e', "bash -c '{command}; read -p \"Press Enter to close...\"'"]),
                ('/usr/bin/x-terminal-emulator', ['x-terminal-emulator', '-e', "bash -c '{command}; read -p \"Press Enter to close...\"'"]),
                ('/usr/bin/xterm', ['xterm', '-e', "bash -c '{command}; read -p \"Press Enter to close...\"'"])
            ]
        
            terminal_found = False
            launch_error = None
        
            for term_path, launch_cmd in terminals:
                if os.path.exists(term_path):
                    try:
                        print(f"Found terminal at: {term_path}")
                        # Format the command
                        formatted_cmd = [arg.format(command=tool) if '{command}' in arg else arg for arg in launch_cmd]
                        print(f"Launching with command: {formatted_cmd}")
                    
                       # Launch the process
                        process = subprocess.Popen(
                        formatted_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                        # Check immediate result
                        time.sleep(0.5)  # Give the process a moment to start
                        if process.poll() is None:  # Process is still running
                                terminal_found = True
                                self.results_text.insert(tk.END, f"Launched tool in {os.path.basename(term_path)}: {tool}\n", 'success')
                                break
                        else:
                            # Get error output if process failed
                            _, stderr = process.communicate()
                            launch_error = stderr.decode() if stderr else "Process terminated immediately"
                            print(f"Failed to launch with {term_path}: {launch_error}")
                        
                    except Exception as e:
                        launch_error = str(e)
                        print(f"Error launching {term_path}: {launch_error}")
                        continue
        
            if not terminal_found:
                error_msg = f"Failed to launch any terminal. Last error: {launch_error}"
                self.results_text.insert(tk.END, f"Error: {error_msg}\n", 'error')
                print(error_msg)

                # Fallback to running in current terminal
                fallback_msg = "Attempting to run tool in current terminal..."
                print(fallback_msg)
                self.results_text.insert(tk.END, f"{fallback_msg}\n", 'warning')

               # Run directly
                subprocess.run(['bash', '-c', tool], check=True)
            
        except Exception as e:
            error_msg = f"Critical error launching tool: {str(e)}"
            self.results_text.insert(tk.END, f"{error_msg}\n", 'error')
            print(error_msg)

            # Print extended debug info
            import traceback
            print("Full error traceback:")
            traceback.print_exc()
    
def check_tool_availability(self):
    """Check if required tools are installed"""
    required_tools = {
        'nmap': 'nmap',
        'hydra': 'hydra',
        'nikto': 'nikto',
        'sqlmap': 'sqlmap',
        'gobuster': 'gobuster',
        'enum4linux': 'enum4linux',
        'wfuzz': 'wfuzz',
        'sslscan': 'sslscan',
        'medusa': 'medusa'
    }
    
    missing_tools = []
    
    for tool, package in required_tools.items():
        if not self._check_tool_exists(tool):
            missing_tools.append(package)
    
    if missing_tools:
        message = "The following tools are missing:\n"
        message += "\n".join(missing_tools)
        message += "\n\nOn Kali Linux, install them with:\n"
        message += f"sudo apt update && sudo apt install {' '.join(missing_tools)}\n"
        self.results_text.insert(tk.END, message, 'warning')

def _check_tool_exists(self, tool):
    """Check if a tool exists in PATH"""
    try:
        result = subprocess.run(['which', tool], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE,
                              text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error checking for tool {tool}: {e}")
        return False
        
    def __init__(self, master):
        self.master = master
        master.title("PortScanPLUS")
        
        # Print debug info about nmap availability
        if NMAP_AVAILABLE:
            print("Nmap is available for use")
        else:
            print("Nmap is not available, will use manual scanning")
        
        # Set window properties
        self._configure_window()
        
        # Initialize styling
        self._initialize_styles()
        
        # Create the main container with padding
        self.main_container = ttk.Frame(master, padding="10")
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Initialize button references
        self.scan_button = None
        self.scan_ports_button = None
        self.choose_host_button = None
        self.choose_port_button = None
        self.start_tools_button = None
        
        # Create all widgets
        self._create_widgets()
        
        # Initialize message queue for updates
        self.message_queue = queue.Queue()
        self._start_ui_updater()
        
        # Check tool availability
        self.check_tool_availability()

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanPlusGUI(root)
    root.mainloop()