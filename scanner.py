import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import struct
import re
import socket
import nmap
from mac_vendor_lookup import MacLookup

well_known_ports = {
        20: 'FTP (File Transfer Protocol)',
        21: 'FTP (File Transfer Protocol)',
        22: 'SSH (Secure Shell)',
        23: 'Telnet',
        25: 'SMTP (Simple Mail Transfer Protocol)',
        53: 'DNS (Domain Name System)',
        80: 'HTTP (Hypertext Transfer Protocol)',
        110: 'POP3 (Post Office Protocol version 3)',
        119: 'NNTP (Network News Transfer Protocol)',
        123: 'NTP (Network Time Protocol)',
        143: 'IMAP (Internet Message Access Protocol)',
        161: 'SNMP (Simple Network Management Protocol)',
        194: 'IRC (Internet Relay Chat)',
        443: 'HTTPS (HTTP Secure)',
        445: 'SMB (Server Message Block)',
        465: 'SMTPS (Simple Mail Transfer Protocol Secure)',
        514: 'Syslog',
        587: 'SMTP (Mail Submission)',
        631: 'IPP (Internet Printing Protocol)',
        873: 'rsync',
        993: 'IMAPS (Internet Message Access Protocol Secure)',
        995: 'POP3S (Post Office Protocol version 3 Secure)',
        1080: 'SOCKS (SOCKetS)',
        1194: 'OpenVPN',
        1433: 'Microsoft SQL Server',
        1434: 'Microsoft SQL Server',
        1521: 'Oracle',
        1723: 'PPTP (Point-to-Point Tunneling Protocol)',
        3306: 'MySQL',
        3389: 'RDP (Remote Desktop Protocol)',
        5432: 'PostgreSQL',
        5900: 'VNC (Virtual Network Computing)',
        5901: 'VNC (Virtual Network Computing)',
        5902: 'VNC (Virtual Network Computing)',
        5903: 'VNC (Virtual Network Computing)',
        6379: 'Redis',
        8080: 'HTTP Alternate (http_alt)',
        8443: 'HTTPS Alternate (https_alt)',
        9000: 'Jenkins',
        9090: 'HTTP Alternate (http_alt)',
        9091: 'HTTP Alternate (http_alt)'
    }


class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        # Create the IP address entry
        self.label = tk.Label(self, text="Digite um IP ou uma rede para escanear:")
        self.label.pack()
        self.ip_entry = tk.Entry(self)
        self.ip_entry.pack()

        # Create the subnet mask entry
        self.subnet_mask_label = tk.Label(self, text="Digite a máscara de sub-rede:")
        self.subnet_mask_label.pack()
        self.subnet_mask_entry = tk.Entry(self)
        self.subnet_mask_entry.pack()

        # Create the port range entry
        self.port_label = tk.Label(self, text="Digite o range de portas (ex. 0-1000, opcional):")
        self.port_label.pack()
        self.port_entry = tk.Entry(self)
        self.port_entry.pack()

        # Create the network scan button
        self.scan_network_button = tk.Button(self, text="Rastrear Rede", command=self.scan_network)
        self.scan_network_button.pack()

        # Create the port scan button
        self.scan_ports_button = tk.Button(self, text="Rastrear Portas", command=self.scan_ports)
        self.scan_ports_button.pack()

    def create_network_table(self, devices):
        # Destroy any existing network table
        if hasattr(self, "network_frame"):
            self.network_frame.destroy()
        
        # Create a new frame for the network table
        self.network_frame = ttk.Frame(self)
        self.network_frame.pack(side=tk.LEFT, padx=10)

        # Create the network table
        self.network_table = ttk.Treeview(self.network_frame, columns=("ip", "mac", "vendor"))
        self.network_table.heading("#0", text="")
        self.network_table.heading("ip", text="IP")
        self.network_table.heading("mac", text="Endereço MAC")
        self.network_table.heading("vendor", text="Fornecedor")
        self.network_table.column("#0", width=0, stretch=tk.NO)
        self.network_table.column("ip", width=150, stretch=tk.YES)
        self.network_table.column("mac", width=150, stretch=tk.YES)
        self.network_table.column("vendor", width=150, stretch=tk.YES)
        self.network_table.pack(side=tk.LEFT, fill=tk.BOTH)

        # Add the devices to the table
        for device in devices:
            self.network_table.insert("", tk.END, values=(device[0], device[1], device[2]))

        # Add a scrollbar to the table
        self.network_scrollbar = ttk.Scrollbar(self.network_frame, orient=tk.VERTICAL, command=self.network_table.yview)
        self.network_table.configure(yscrollcommand=self.network_scrollbar.set)
        self.network_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_port_table(self, ports):
        # Destroy any existing port table
        if hasattr(self, "port_frame"):
            self.port_frame.destroy()

        # Create a new frame for the port table
        self.port_frame = ttk.Frame(self)
        self.port_frame.pack(side=tk.LEFT, padx=10)

        # Create the port table
        self.port_table = ttk.Treeview(self.port_frame, columns=("port", "service"))
        self.port_table.heading("#0", text="")
        self.port_table.heading("port", text="Porta")
        self.port_table.heading("service", text="Serviço")
        self.port_table.column("#0", width=0, stretch=tk.NO)
        self.port_table.column("port", width=150, stretch=tk.YES)
        self.port_table.column("service", width=150, stretch=tk.YES)
        self.port_table.pack(side=tk.LEFT, fill=tk.BOTH)

        # Add the ports to the table
        for port in ports:
            self.port_table.insert("", tk.END, values=(port[0], port[1]))

        # Add a scrollbar to the table
        self.port_scrollbar = ttk.Scrollbar(self.port_frame, orient=tk.VERTICAL, command=self.port_table.yview)
        self.port_table.configure(yscrollcommand=self.port_scrollbar.set)
        self.port_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def scan_network(self):
        # Get the IP address and subnet mask from the user input
        ip_address = self.ip_entry.get()
        subnet_mask = self.subnet_mask_entry.get()

        # Combine the IP address and subnet mask to form the network address
        network_address = ip_address + "/" + subnet_mask

        # Escaneia a rede
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network_address, arguments="-sP -n")
        except nmap.nmap.PortScannerError:
            messagebox.showerror("Erro", "Ocorreu um erro ao escanear a rede.")
            return

        # Lista os dispositivos encontrados
        devices = []
        for host in nm.all_hosts():
            # try to get the MAC address else set it to "Unknown"
            try:
                mac_address = nm[host]["addresses"]["mac"]
            except KeyError:
                mac_address = "Unknown"

            # try to get the vendor name else set it to "Unknown"
            try:
                vendor = nm[host]["vendor"][mac_address]
            except KeyError:
                vendor = "Unknown"

            # add the device to the list
            devices.append((host, mac_address, vendor))
            
        # create a new table
        self.create_network_table(devices)


    def scan_ports(self):
        # Get the IP address and port range from the user input
        ip_address = self.ip_entry.get()
        # if no port range is specified, use the default
        if self.port_entry.get() == "":
            port_range = "1-65535"
        else:
            port_range = self.port_entry.get()
        
        # Escaneia as portas
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip_address, arguments="-p " + port_range)
        except nmap.nmap.PortScannerError:
            messagebox.showerror("Erro", "Ocorreu um erro ao escanear as portas.")
            return
        
        # Lista as portas encontradas
        ports = []
        for host in nm.all_hosts():
            # if is valid port
            if "tcp" in nm[host]:
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        try:
                            service = well_known_ports[port]
                        except KeyError:
                            service = "Unknown"
                        ports.append((port, service))
                    
        # create a new table
        self.create_port_table(ports)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Rastreador de Rede")
    app = Application(master=root)
    app.mainloop()
