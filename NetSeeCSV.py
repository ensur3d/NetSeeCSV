#!/usr/bin/env python3
"""
NetSeeCSV for Linux
Displays all active TCP/UDP connections including IPv4 and IPv6
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, TclError
import subprocess
import threading
import re
import os
import logging
from datetime import datetime

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSeeCSV")
        self.root.geometry("1600x900")
        
        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Variables
        self.connections = []
        self.refreshing = False
        self.auto_refresh_enabled = False
        self.auto_refresh_interval = 5000  # 5 seconds
        self.auto_refresh_job = None
        
        # GUI
        self.create_menu()
        self.create_toolbar()
        self.create_treeview()
        self.create_status_bar()
        
        # Initialize dark mode after GUI is created
        self.dark_mode = False
        self.apply_style()
        
        # Start with initial refresh
        self.refresh_connections()
        
        # Start auto-refresh if enabled
        if self.auto_refresh_enabled:
            self.start_auto_refresh()
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Refresh", command=self.refresh_connections)
        file_menu.add_command(label="Export to CSV", command=self.export_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", command=self.refresh_connections)
        view_menu.add_command(label="Auto-refresh", command=self.toggle_auto_refresh)
        self.dark_mode_var = tk.BooleanVar()
        view_menu.add_checkbutton(label="Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
    def create_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="Refresh", command=self.refresh_connections).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Filter", command=self.show_filters).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export", command=self.export_csv).pack(side=tk.LEFT, padx=2)
        
        # Auto-refresh checkbox
        self.auto_refresh_var = tk.BooleanVar()
        ttk.Checkbutton(toolbar, text="Auto-refresh", variable=self.auto_refresh_var, 
                       command=self.toggle_auto_refresh).pack(side=tk.RIGHT, padx=2)
        
    def create_treeview(self):
        # Create treeview frame
        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview with scrollbars
        columns = ("Protocol", "Local Address", "Remote Address", "State", "PID", "Process", "Local Port", "Remote Port")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=30)
        
        # Define headings
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
            self.tree.column(col, width=120)
            
        # Configure column widths
        self.tree.column("Protocol", width=80)
        self.tree.column("Local Address", width=220)
        self.tree.column("Remote Address", width=220)
        self.tree.column("State", width=120)
        self.tree.column("PID", width=80)
        self.tree.column("Process", width=180)
        self.tree.column("Local Port", width=100)
        self.tree.column("Remote Port", width=100)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Show Connection Info", command=self.show_connection_details)
        self.context_menu.add_command(label="Kill Process", command=self.kill_process)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Local Address", command=self.copy_local_address)
        self.context_menu.add_command(label="Copy Remote Address", command=self.copy_remote_address)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        
    def create_status_bar(self):
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def show_context_menu(self, event):
        try:
            self.tree.selection_set(self.tree.identify_row(event.y))
            self.context_menu.tk_popup(event.x_root, event.y_root)
        except Exception as e:
            logger.error(f"Error showing context menu: {e}")
            pass
            
    def show_filters(self):
        # Simple filter dialog
        filter_window = tk.Toplevel(self.root)
        filter_window.title("Filter Connections")
        filter_window.geometry("300x250")
        filter_window.transient(self.root)
        filter_window.grab_set()
        
        # Context menu for paste functionality
        context_menu = tk.Menu(filter_window, tearoff=0)
        context_menu.add_command(label="Paste", command=lambda: self.paste_to_focused(filter_window, addr_entry))
        
        def show_context_menu(event):
            focused = filter_window.focus_get()
            if focused == addr_entry or focused == protocol_combo or focused == state_combo or focused == port_entry:
                context_menu.tk_popup(event.x_root, event.y_root)
        
        filter_window.bind("<Button-3>", show_context_menu)
        
        # Protocol filter
        ttk.Label(filter_window, text="Protocol:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        protocol_var = tk.StringVar()
        protocol_combo = ttk.Combobox(filter_window, textvariable=protocol_var, 
                                     values=["All", "TCP", "UDP", "TCP6", "UDP6"])
        protocol_combo.set("All")
        protocol_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # State filter
        ttk.Label(filter_window, text="State:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        state_var = tk.StringVar()
        state_combo = ttk.Combobox(filter_window, textvariable=state_var,
                                  values=["All", "ESTAB", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "UNCONN"])
        state_combo.set("All")
        state_combo.grid(row=1, column=1, padx=5, pady=5)
        
        # Address filter
        ttk.Label(filter_window, text="Address Filter:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        addr_var = tk.StringVar()
        addr_entry = ttk.Entry(filter_window, textvariable=addr_var)
        addr_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Port filter
        ttk.Label(filter_window, text="Port Filter:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        port_var = tk.StringVar()
        port_entry = ttk.Entry(filter_window, textvariable=port_var)
        port_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Apply button
        ttk.Button(filter_window, text="Apply", command=lambda: self.apply_filters(
            protocol_var.get(), state_var.get(), addr_var.get(), port_var.get(), filter_window)).grid(row=4, column=0, columnspan=2, pady=10)
        
    def apply_filters(self, protocol, state, address_filter, port_filter, window):
        # Filter the connections based on the criteria
        filtered_connections = []
        
        # Get the original connections
        original_connections = self.connections
        
        for conn in original_connections:
            # Apply protocol filter - convert to lowercase for comparison
            if protocol != "All" and protocol.lower() != conn['protocol'].lower():
                continue
                
            # Apply state filter
            if state != "All" and state != conn['state']:
                continue
                
            # Apply address filter - connection should match either local OR remote address
            if address_filter and address_filter not in conn['local_addr'] and address_filter not in conn['remote_addr']:
                continue
            
            # Apply port filter - connection should match either local port OR remote port
            if port_filter and port_filter not in str(conn.get('port', '')) and port_filter not in str(conn.get('remote_port', '')):
                continue
                
            # If we get here, the connection matches all filters
            filtered_connections.append(conn)
            
        # Update the treeview with filtered connections
        self.update_connection_tree(filtered_connections)
        
        # Close the filter window
        window.destroy()
        
    def refresh_connections(self):
        if self.refreshing:
            return
            
        self.refreshing = True
        self.status_bar.config(text="Refreshing connections...")
        self.root.update()
        
        # Run in separate thread to avoid freezing GUI
        thread = threading.Thread(target=self._refresh_connections_thread)
        thread.daemon = True
        thread.start()
        
    def _validate_commands(self, commands):
        """
        Validate and sanitize commands to ensure only allowed commands can be executed.
        This prevents command injection by strictly whitelisting allowed commands and arguments.
        """
        # Define the exact whitelist of allowed commands and their arguments
        ALLOWED_WHITELIST = {
            ('ss', '-tulnpa'),
            ('ss', '-tulnp', '-o'),
        }
        
        validated = []
        
        for cmd in commands:
            # Ensure command is a list/tuple
            if not isinstance(cmd, (list, tuple)):
                raise ValueError(f"Invalid command format: {cmd}")
            
            # Ensure all elements are strings
            if not all(isinstance(arg, str) for arg in cmd):
                raise ValueError(f"Command contains non-string arguments: {cmd}")
            
            # Check for dangerous characters that could indicate injection attempts
            dangerous_chars = [';', '&', '|', '$', '`', '>', '<', '*', '?', '{', '}', '[', ']']
            for arg in cmd:
                for char in dangerous_chars:
                    if char in arg:
                        raise ValueError(f"Potentially dangerous character '{char}' found in command: {cmd}")
            
            # Convert to tuple for whitelist comparison
            cmd_tuple = tuple(cmd)
            
            # Strict whitelist validation - only exact matches allowed
            if cmd_tuple not in ALLOWED_WHITELIST:
                raise ValueError(f"Command not in allowed whitelist: {cmd}")
            
            # Command is validated - convert back to list for subprocess
            validated.append(list(cmd))
        
        return validated
        
    def _refresh_connections_thread(self):
        try:
            connections = []
            
            # Define allowed commands whitelist - only these specific commands are permitted
            # Each command must be a list of strings with exact allowed arguments
            ALLOWED_COMMANDS = [
                ['ss', '-tulnpa'],  # All TCP/UDP connections with process info
                ['ss', '-tulnp', '-o'],  # With timers
            ]
            
            # Validate and sanitize commands
            validated_commands = self._validate_commands(ALLOWED_COMMANDS)
            
            for cmd in validated_commands:
                try:
                    # nosec B603 - Commands are strictly validated through _validate_commands() whitelist
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        connections.extend(self.parse_ss_output(result.stdout))
                except Exception as e:
                    logger.error(f"Error running command {cmd}: {e}")
                    continue
            
            # Remove duplicates while preserving order
            seen = set()
            unique_connections = []
            for conn in connections:
                # Create a unique key based on local address, remote address, and protocol
                key = (conn['local_addr'], conn['remote_addr'], conn['protocol'])
                if key not in seen:
                    seen.add(key)
                    unique_connections.append(conn)
            
            self.root.after(0, lambda: self.update_connection_tree(unique_connections))
            
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: messagebox.showerror("Error", "Command timed out"))
            self.root.after(0, self._refresh_complete)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error refreshing connections: {str(e)}"))
            self.root.after(0, self._refresh_complete)
            
    def parse_ss_output(self, output):
        connections = []
        
        # Skip header lines
        lines = output.strip().split('\n')
        
        # Find the line with column headers
        header_line = None
        for i, line in enumerate(lines):
            if line.strip().startswith('Netid'):
                header_line = i
                break
        
        if header_line is None:
            # If we can't find the header, process all lines
            lines_to_process = lines
        else:
            lines_to_process = lines[header_line + 1:]
        
        for line in lines_to_process:
            if not line.strip():
                continue
                
            try:
                # More robust parsing approach for ss output
                # The ss output format is: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                # We'll use regex to properly extract fields
                
                # Split by whitespace but preserve the structure
                # Use split with maxsplit to avoid issues with IPv6 addresses containing colons
                parts = line.split(None, 6)  # Split by any whitespace, max 7 parts
                
                if len(parts) < 6:
                    # If we don't have enough parts, try to get what we can
                    if len(parts) >= 6:
                        # At least we have the basic fields
                        pass
                    else:
                        continue
                
                # Extract the fields properly
                protocol = parts[0] if len(parts) > 0 else ""
                state = parts[1] if len(parts) > 1 else ""
                recv_q = parts[2] if len(parts) > 2 else ""
                send_q = parts[3] if len(parts) > 3 else ""
                local_addr_port = parts[4] if len(parts) > 4 else ""
                remote_addr_port = parts[5] if len(parts) > 5 else ""
                
                # Extract PID and process name if available
                pid = "-"
                process = "-"
                
                # Process info is in the 7th field if it exists
                if len(parts) > 6:
                    process_info = parts[6]
                    if process_info.startswith('users:('):
                        # Process info in format: users:(("process_name",pid=1234,fd=56))
                        try:
                            # Extract PID
                            pid_match = re.search(r'pid=(\d+)', process_info)
                            if pid_match:
                                pid = pid_match.group(1)
                            
                            # Extract process name - more robust extraction
                            # Try to match the process name directly from the users:(("name",...) format
                            name_match = re.search(r'users:\(\("([^"]+)",', process_info)
                            if name_match:
                                process = name_match.group(1)
                            else:
                                # Fallback: try to extract from quotes in the process info
                                name_match = re.search(r'"([^"]+)"', process_info)
                                if name_match:
                                    process = name_match.group(1)
                        except Exception as e:
                            logger.warning(f"Error extracting process info: {e}")
                            pass
                
                # Extract remote port
                remote_port = self.extract_port(remote_addr_port)
                
                # Only add connection if we have the basic info
                if local_addr_port and remote_addr_port:
                    connections.append({
                        'protocol': protocol,
                        'local_addr': local_addr_port,
                        'remote_addr': remote_addr_port,
                        'state': state,
                        'pid': pid,
                        'process': process,
                        'port': self.extract_port(local_addr_port),
                        'remote_port': remote_port
                    })
                
            except Exception as e:
                logger.warning(f"Error parsing line: {line} - {e}")
                continue
                
        return connections
        
    def extract_port(self, address):
        """Extract port from address string"""
        try:
            if ':' in address:
                # Handle IPv6 addresses that contain brackets
                if address.startswith('[') and ']' in address:
                    # IPv6 address with brackets
                    port_start = address.rfind(':') + 1
                    return address[port_start:]
                else:
                    # IPv4 or IPv6 without brackets
                    return address.split(':')[-1]
            return "N/A"
        except:
            return "N/A"
            
    def update_connection_tree(self, connections):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add new items
        for conn in connections:
            self.tree.insert("", tk.END, values=(
                conn['protocol'],
                conn['local_addr'],
                conn['remote_addr'],
                conn['state'],
                conn['pid'],
                conn['process'],
                conn['port'],
                conn['remote_port']
            ))
            
        # Update status bar
        count = len(connections)
        self.status_bar.config(text=f"Showing {count} connections")
        self.connections = connections
        self._refresh_complete()
        
    def _refresh_complete(self):
        self.refreshing = False
        
    def sort_treeview(self, column):
        # Simple sorting implementation
        items = [(self.tree.set(child, column), child) for child in self.tree.get_children('')]
        items.sort(reverse=column == "Remote Port")
        
        for index, (val, child) in enumerate(items):
            self.tree.move(child, '', index)
            
    def show_connection_details(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        item = self.tree.item(selected[0])
        values = item['values']
        
        details = f"Protocol: {values[0]}\n"
        details += f"Local Address: {values[1]}\n"
        details += f"Remote Address: {values[2]}\n"
        details += f"State: {values[3]}\n"
        details += f"PID: {values[4]}\n"
        details += f"Process: {values[5]}\n"
        details += f"Local Port: {values[6]}\n"
        details += f"Remote Port: {values[7]}"
        
        messagebox.showinfo("Connection Details", details)
        
    def kill_process(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        item = self.tree.item(selected[0])
        pid = item['values'][4]
        
        if pid == "-" or pid == "N/A":
            messagebox.showwarning("Warning", "No PID available for this connection")
            return
            
        try:
            if messagebox.askyesno("Confirm", f"Kill process with PID {pid}?"):
                os.kill(int(pid), 9)
                messagebox.showinfo("Success", f"Process {pid} killed successfully")
                self.refresh_connections()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill process: {str(e)}")
            
    def copy_local_address(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        item = self.tree.item(selected[0])
        address = item['values'][1]  # Local address
        self.root.clipboard_clear()
        self.root.clipboard_append(address)
        
    def copy_remote_address(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        item = self.tree.item(selected[0])
        address = item['values'][2]  # Remote address
        self.root.clipboard_clear()
        self.root.clipboard_append(address)
        
    def paste_to_focused(self, window, entry_widget):
        try:
            clipboard_text = window.clipboard_get()
            focused = window.focus_get()
            if hasattr(focused, 'insert'):
                focused.insert(tk.INSERT, clipboard_text)
        except:
            pass
        
    def export_csv(self):
        if not self.connections:
            messagebox.showwarning("Warning", "No connections to export")
            return
        
        # Hide hidden files in file dialog
        try:
            try:
                self.root.tk.call('tk_getOpenFile', '-foobarbaz')
            except TclError:
                pass
            self.root.tk.call('set', '::tk::dialog::file::showHiddenBtn', '0')
            self.root.tk.call('set', '::tk::dialog::file::showHiddenVar', '0')
        except:
            pass
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w') as f:
                # Write header
                f.write("Protocol,Local Address,Remote Address,State,PID,Process,Local Port,Remote Port\n")
                
                # Write data
                for conn in self.connections:
                    f.write(f"{conn['protocol']},{conn['local_addr']},{conn['remote_addr']},"
                           f"{conn['state']},{conn['pid']},{conn['process']},{conn['port']},{conn['remote_port']}\n")
                    
            messagebox.showinfo("Success", f"Connections exported to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")
            
    def toggle_auto_refresh(self):
        self.auto_refresh_enabled = self.auto_refresh_var.get()
        if self.auto_refresh_enabled:
            self.start_auto_refresh()
            messagebox.showinfo("Auto-refresh", "Auto-refresh enabled")
        else:
            self.stop_auto_refresh()
            messagebox.showinfo("Auto-refresh", "Auto-refresh disabled")
            
    def start_auto_refresh(self):
        self.stop_auto_refresh()  # Stop any existing auto-refresh
        self.auto_refresh_job = self.root.after(self.auto_refresh_interval, self.refresh_connections)
        
    def stop_auto_refresh(self):
        if self.auto_refresh_job:
            self.root.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None
            
    def show_about(self):
        about_text = (
            "NetSeeCSV\n"
            "Displays all active TCP/UDP connections on Linux\n"
            "Supports IPv4 and IPv6 addresses\n\n"
            "Features:\n"
            "- Shows all active connections (listening, established, etc.)\n"
            "- Filter by TCP/UDP, Addresses, Port and State\n"
            "- Export to CSV\n"
            "- Auto-refresh functionality\n"
            "- Dark Mode\n"
            "- Kill processes listed with connection\n"
        )
        messagebox.showinfo("About", about_text)
        
    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.apply_style()
        
    def apply_style(self):
        # Configure ttk theme
        self.style.theme_use('clam')
        
        if self.dark_mode:
            # Configure dark mode styles
            self.style.configure('Treeview', 
                               background='#333333',
                               foreground='#ffffff',
                               fieldbackground='#333333',
                               rowheight=25)
            self.style.map('Treeview', 
                          background=[('selected', '#4a4a4a')],
                          foreground=[('selected', '#ffffff')])
            self.style.configure('Treeview.Heading', 
                               background='#3a3a3a',
                               foreground='#ffffff',
                               font=('Arial', 10, 'bold'))
            
            # Configure other widgets for dark mode
            self.root.configure(bg='#2b2b2b')
            self.style.configure('TFrame', background='#2b2b2b')
            self.style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
            self.style.configure('TCheckbutton', background='#2b2b2b', foreground='#ffffff')
            
            # Update menu bar for dark mode
            self.root.option_add('*Menu.background', '#2b2b2b')
            self.root.option_add('*Menu.foreground', '#ffffff')
            self.root.option_add('*Menu.activeBackground', '#4a4a4a')
            self.root.option_add('*Menu.activeForeground', '#ffffff')
            
        else:
            # Configure light mode styles
            self.style.configure('Treeview', 
                               background='#ffffff',
                               foreground='#000000',
                               fieldbackground='#ffffff',
                               rowheight=25)
            self.style.map('Treeview', 
                          background=[('selected', '#3478e8')],
                          foreground=[('selected', '#ffffff')])
            self.style.configure('Treeview.Heading', 
                               background='#e0e0e0',
                               foreground='#000000',
                               font=('Arial', 10, 'bold'))
            
            # Configure other widgets for light mode
            self.root.configure(bg='#f0f0f0')
            self.style.configure('TFrame', background='#f0f0f0')
            self.style.configure('TLabel', background='#f0f0f0', foreground='#000000')
            self.style.configure('TCheckbutton', background='#f0f0f0', foreground='#000000')
            
            # Update menu bar for light mode
            self.root.option_add('*Menu.background', '#f0f0f0')
            self.root.option_add('*Menu.foreground', '#000000')
            self.root.option_add('*Menu.activeBackground', '#3478e8')
            self.root.option_add('*Menu.activeForeground', '#ffffff')
            
        # Update the context menu to match current mode
        if self.context_menu:
            bg_color = '#2b2b2b' if self.dark_mode else '#f0f0f0'
            fg_color = '#ffffff' if self.dark_mode else '#000000'
            self.context_menu.configure(bg=bg_color, fg=fg_color)
            for i in range(self.context_menu.index(tk.END) + 1):
                try:
                    # Check if entry type supports foreground/background (separators don't)
                    entry_type = self.context_menu.type(i)
                    if entry_type in ['cascade', 'command', 'checkbutton', 'radiobutton']:
                        self.context_menu.entryconfig(i, background=bg_color, foreground=fg_color)
                except Exception:
                    # Silently skip entries that don't support color config (separators, tearoffs)
                    pass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def main():
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
