import os
from .suricatasc import SuricataSC, SuricataException


class SuricataIntegration:
    def __init__(self, socket_path="/var/run/suricata/suricata-command.socket"):
        self.sc = SuricataSC(socket_path)
        try:
            self.sc.connect()
        except SuricataException as e:
            print(f"Error connecting to Suricata: {e}")

    def __del__(self):
        if hasattr(self, "sc"):
            self.sc.close()

    def get_version(self):
        try:
            return self.sc.send_command("version")["message"]
        except SuricataException as e:
            return f"Error getting version: {e}"

    def get_running_status(self):
        try:
            return self.sc.send_command("uptime")["message"]
        except SuricataException as e:
            return f"Error getting status: {e}"

    def reload_rules(self):
        try:
            return self.sc.send_command("reload-rules")["message"]
        except SuricataException as e:
            return f"Error reloading rules: {e}"

    def get_pcap_stats(self):
        try:
            return self.sc.send_command("pcap-file-list")["message"]
        except SuricataException as e:
            return f"Error getting PCAP stats: {e}"

    def analyze_pcap(self, pcap_file):
        if not os.path.exists(pcap_file):
            return f"Error: PCAP file {pcap_file} does not exist"
        try:
            return self.sc.send_command("pcap-file", {"filename": pcap_file})["message"]
        except SuricataException as e:
            return f"Error analyzing PCAP: {e}"

    # Add more methods as needed for specific Suricata commands
