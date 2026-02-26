import os
import psutil
import socket
import json
import threading
import queue
import requests
import logging
from datetime import datetime
from scapy.all import sniff, TCP, UDP, IP, Ether

# ---------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------
# Set up professional logging to track agent health and activity
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("agent.log"), # Log persistent data for forensic analysis
        logging.StreamHandler()           # Real-time console output
    ]
)

# ---------------------------------------------------------
# Environment Configuration
# ---------------------------------------------------------
# Use environment variables for flexible deployment (Docker/Cloud/Local)
MANAGER_IP = os.getenv('MANAGER_IP', '127.0.0.1')
MANAGER_PORT = int(os.getenv('MANAGER_PORT', 2053))
SERVER_ADDRESS = (MANAGER_IP, MANAGER_PORT)

class NetworkAgent:
    """
    A distributed network agent responsible for sniffing, analyzing, 
    and reporting local traffic to a centralized Manager.
    """
    def __init__(self, config_path="config.json"):
        # thread-safe queue to pass packets from sniffer to processor
        self.packet_queue = queue.Queue()
        
        # UDP socket for high-performance, low-overhead data transmission
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.my_ip = self.get_my_ip()
        
        # Caching mechanisms to reduce API calls and system overhead
        self.country_cache = {}
        self.software_cache = {}
        
        logging.info(f"Agent initialized. Manager: {MANAGER_IP}:{MANAGER_PORT}, Local IP: {self.my_ip}")

    def get_my_ip(self):
        """Retrieves the local primary IP address by simulating an external connection."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Does not actually establish a connection; used to find the routing interface
            s.connect(('8.8.8.8', 80))
            my_ip = s.getsockname()[0]
        except Exception as e:
            logging.warning(f"Could not determine local IP, defaulting to 127.0.0.1. Error: {e}")
            my_ip = '127.0.0.1'
        finally:
            s.close()
        return my_ip

    def get_country(self, ip_address):
        """Performs a Geo-IP lookup with local caching for external destinations."""
        if ip_address in self.country_cache:
            return self.country_cache[ip_address]

        # Categorize private/local network segments
        if ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('127.'):
            self.country_cache[ip_address] = 'Local'
            return 'Local'

        try:
            # Query external Geo-IP API
            url = f'http://ip-api.com/json/{ip_address}?fields=status,country'
            response = requests.get(url, timeout=2)
            data = response.json()
            country = data.get('country', 'Unknown') if data.get('status') == 'success' else 'Unknown'
        except Exception as e:
            logging.debug(f"Geo-IP lookup failed for {ip_address}: {e}")
            country = 'Unknown'

        self.country_cache[ip_address] = country
        return country

    def get_software(self, ip, port):
        """Maps a specific network connection to the local process name using psutil."""
        address_key = f"{ip}:{port}"
        if address_key in self.software_cache:
            return self.software_cache[address_key]

        software_name = "Unknown"
        try:
            # Iterate through active system connections
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                match_remote = conn.raddr and conn.raddr.ip == ip and conn.raddr.port == port
                match_local = conn.laddr and conn.laddr.ip == ip and conn.laddr.port == port
                
                if (match_remote or match_local) and conn.pid:
                    try:
                        # Extract process name from PID
                        process = psutil.Process(conn.pid)
                        software_name = process.name()
                        break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            logging.debug(f"Process lookup error for {address_key}: {e}")

        self.software_cache[address_key] = software_name
        return software_name

    def filter_packets(self, packet):
        """LFilter: Ensures only IP packets with L4 protocols (TCP/UDP) are processed."""
        return packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP))

    def packet_handler(self, packet):
        """Queue producer: Hands off raw packets to the processing queue."""
        self.packet_queue.put(packet)

    def sniffing_thread(self):
        """Thread 1: Low-level packet capture using Scapy."""
        logging.info(f"Sniffing thread started on {self.my_ip}...")
        try:
            # store=0 prevents memory leaks during long-term monitoring
            sniff(lfilter=self.filter_packets, prn=self.packet_handler, store=False)
        except Exception as e:
            logging.critical(f"Sniffing thread crashed: {e}")

    def processing_thread(self):
        """Thread 2: Queue consumer: Analyzes, enriches, and ships data."""
        logging.info("Processing thread started...")
        while True:
            packet = self.packet_queue.get()
            try:
                ip_layer = packet[IP]
                is_incoming = ip_layer.src != self.my_ip
                
                target_ip = ip_layer.src if is_incoming else ip_layer.dst
                mac_addr = packet[Ether].src if is_incoming else packet[Ether].dst
                
                # Determine port based on the active L4 layer
                if packet.haslayer(TCP):
                    port = packet[TCP].sport if is_incoming else packet[TCP].dport
                else:
                    port = packet[UDP].sport if is_incoming else packet[UDP].dport

                # Construct JSON telemetry for the Manager
                payload = {
                    "timestamp": datetime.now().isoformat(),
                    "direction": "in" if is_incoming else "out",
                    "destination_ip": target_ip,
                    "port": port,
                    "size_bytes": len(packet),
                    "country": self.get_country(target_ip),
                    "software_name": self.get_software(target_ip, port),
                    "mac": mac_addr
                }

                # Encode and transmit via UDP
                json_data = json.dumps(payload).encode('utf-8')
                self.sock.sendto(json_data, SERVER_ADDRESS)
                logging.debug(f"Sent: {payload['software_name']} to {target_ip}")
                
            except Exception as e:
                logging.error(f"Error processing packet: {e}")
            finally:
                # Cleanup: ensure queue tracking remains accurate
                self.packet_queue.task_done()

    def run(self):
        """Initialize and manage lifecycle of parallel monitoring threads."""
        t1 = threading.Thread(target=self.sniffing_thread, daemon=True)
        t2 = threading.Thread(target=self.processing_thread, daemon=True)
        
        t1.start()
        t2.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Agent stopped by user.")

if __name__ == "__main__":
    import time
    agent = NetworkAgent()
    agent.run()