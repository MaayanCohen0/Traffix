import json
import os

# Define the path to our configuration file
CONFIG_FILE = "config.json"

class ConfigManager:
    """
    Manages system configurations with support for dynamic on-the-fly reloading.
    """
    def __init__(self, config_path=CONFIG_FILE):
        self.config_path = config_path
        self._last_mtime = 0 # Track file modification time for performance
        self._config_cache = {}
        self.load_config()

    def load_config(self):
        """
        Loads the JSON config file from disk.
        Implements a 'lazy read' strategy: only reads if the file was modified.
        """
        if not os.path.exists(self.config_path):
            print(f"[!] Warning: Configuration file {self.config_path} not found.")
            # Critical: Provide hardcoded defaults if the file is missing
            self._config_cache = {
                "server": {"host": "127.0.0.1", "port": 2053},
                "security": {"blacklist_ips": []}
            }
            return

        try:
            # Check the "Modified Time" (mtime) from the OS metadata
            current_mtime = os.path.getmtime(self.config_path)
            
            # Hot-reloading: reload data only if the file timestamp has changed
            if current_mtime > self._last_mtime:
                with open(self.config_path, 'r') as f:
                    self._config_cache = json.load(f)
                self._last_mtime = current_mtime
                print("[*] Configuration reloaded successfully from disk.")
                
        except Exception as e:
            # Fallback to current cache if a reload fails (e.g., during a manual edit)
            print(f"[!] Error loading config file: {e}")

    def get_blacklist(self):
        """
        Retrieves the latest blacklist of suspicious IP addresses.
        Triggers an mtime check to ensure fresh data.
        """
        self.load_config() 
        return self._config_cache.get("security", {}).get("blacklist_ips", [])

    def get_server_settings(self):
        """
        Retrieves network parameters (Host/Port) for the UDP listener.
        """
        self.load_config()
        server_config = self._config_cache.get("server", {})
        return server_config.get("host", "127.0.0.1"), server_config.get("port", 2053)
    
    def get_agent_name(self, ip_address):
        """Returns a friendly name for an IP if defined in config, else returns a default name."""
        self.load_config()
        names = self._config_cache.get("agent_names", {})
        return names.get(ip_address, f"Agent_{ip_address}")

# Global singleton instance for the Manager to import
config = ConfigManager()