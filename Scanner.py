import socket
import threading

class PortScanner:
    def __init__(self, ip):    # Initialize with target IP address
        self.ip = ip
        self.open_ports = []
    
    def __repr__(self):    # String representation of the object
        return f'PortScanner: {self.ip}'
    
    def add_port(self, port):    # Add open port to the list
        self.open_ports.append(port)
    
    def is_host_unreachable(self):    # Check if host is reachable
        try:
            socket.gethostbyname(self.ip)    # Resolve hostname to IP address
            return True
        except socket.gaierror as e:    # Handle DNS resolution errors
            print(f"Error: Host {self.ip} is unreachable: {e}")
            return False
    
    def is_validport(self, port):    # Validate port number
        return isinstance(port, int) and 0 < port < 65536
    
    def scan(self, ports): # Scan ports in the given range
        if not self.is_host_unreachable():
            print("Host is unreachable.")
            return False
             
        for port in ports:
            if not self.is_validport(port):
                print(f"Skipping invalid port: {port}")
                continue
            
            if(self.is_open(port)):
                self.add_port(port)
                print(f"[+] Port {port} is open")    # Print open port 
            else:
                print(f"[-] Port {port} is closed")  # Print closed port
        return True         
        
    def is_open(self, port):    # Check if port is open
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)     # timeout for socket connection
                result = s.connect_ex((self.ip, port))    # returns 0 if port is open
        except socket.error as e:    # Handle socket errors
            print(f"Error scanning port {port}  : {e}")
            return False
        
        return result == 0
           
def main ():
    ip = 'scanme.nmap.org'  # Localhost IP address
    
    ports = [21, 22, 80, 443] # Scan ports
    
    scanner = PortScanner(ip)
    if scanner.scan(ports):
        print("\nScan complete.")
        print("Open ports:", scanner.open_ports)
    else:
        print("Host is unreachable.")
    
if __name__ == "__main__":    # Run the main function
    main()