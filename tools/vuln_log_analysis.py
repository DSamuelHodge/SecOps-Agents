# This Python script defines classes for security analysis tasks.
# It includes functionalities for vulnerability assessment and log analysis.


import re
import socket
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Union


@dataclass
class PortInfo:
    port: int
    service: str

@dataclass
class VulnerabilityAssessment:
    target: str
    open_ports: List[PortInfo] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)

@dataclass
class LogAnalysisResult:
    total_logs_processed: int
    event_summary: Dict[str, int]
    suspicious_ips: List[str]
    suspicious_users: List[str]
    user_activities: Dict[str, List[str]]

class SecurityAnalyzer:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080]
        self.common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL"
        }
        self.log_patterns = {
            'failed_login': r'Failed login.*from (\d+\.\d+\.\d+\.\d+)',
            'successful_login': r'Successful login.*for user (\w+)',
            'file_access': r'File access: (\/\S+) by user (\w+)',
            'privilege_escalation': r'Privilege escalation attempt by user (\w+)',
            'malware_detection': r'Malware detected: (\S+) in file (\/\S+)'
        }

    def assess_vulnerabilities(self, target: str) -> VulnerabilityAssessment:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            raise ValueError(f"Invalid IP address: {target}")

        open_ports = self._scan_ports(str(ip))
        vulnerabilities = self._check_common_vulnerabilities(str(ip), open_ports)

        return VulnerabilityAssessment(
            target=str(ip),
            open_ports=open_ports,
            vulnerabilities=vulnerabilities
        )

    def _scan_ports(self, ip: str) -> List[PortInfo]:
        open_ports = []
        for port in self.common_ports:
            if self._is_port_open(ip, port):
                service = self._identify_service(ip, port)
                open_ports.append(PortInfo(port=port, service=service))
        return open_ports

    def _is_port_open(self, ip: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            return result == 0

    def _identify_service(self, ip: str, port: int) -> str:
        if port in self.common_services:
            return self.common_services[port]
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"

    def _check_common_vulnerabilities(self, ip: str, open_ports: List[PortInfo]) -> List[str]:
        vulnerabilities = []
        for port_info in open_ports:
            if port_info.service == "FTP" and port_info.port == 21:
                vulnerabilities.append("Potential insecure FTP server (port 21 open)")
            elif port_info.service == "Telnet" and port_info.port == 23:
                vulnerabilities.append("Insecure Telnet server detected (port 23 open)")
            elif port_info.service == "HTTP" and port_info.port == 80:
                vulnerabilities.append("Unencrypted HTTP server (consider using HTTPS)")
            elif port_info.service == "SMB" and port_info.port == 445:
                vulnerabilities.append("SMB port open (potential vulnerability to worms and ransomware)")
        return vulnerabilities

    def analyze_logs(self, log_data: str) -> LogAnalysisResult:
        log_entries = log_data.split('\n')
        event_counts = {event: 0 for event in self.log_patterns.keys()}
        ip_attempts = {}
        user_activities = {}

        for log_entry in log_entries:
            self._process_log_entry(log_entry, event_counts, ip_attempts, user_activities)

        suspicious_ips = [ip for ip, count in ip_attempts.items() if count > 5]
        suspicious_users = [user for user, activities in user_activities.items() if 'privilege_escalation' in activities]

        return LogAnalysisResult(
            total_logs_processed=len(log_entries),
            event_summary=event_counts,
            suspicious_ips=suspicious_ips,
            suspicious_users=suspicious_users,
            user_activities=user_activities
        )

    def _process_log_entry(self, log_entry: str, event_counts: Dict[str, int],
                           ip_attempts: Dict[str, int], user_activities: Dict[str, List[str]]):
        for event, pattern in self.log_patterns.items():
            match = re.search(pattern, log_entry)
            if match:
                event_counts[event] += 1
                self._update_ip_attempts(event, match, ip_attempts)
                self._update_user_activities(event, match, user_activities)

    def _update_ip_attempts(self, event: str, match: re.Match, ip_attempts: Dict[str, int]):
        if event == 'failed_login':
            ip = match.group(1)
            ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

    def _update_user_activities(self, event: str, match: re.Match, user_activities: Dict[str, List[str]]):
        if event in ['successful_login', 'file_access', 'privilege_escalation']:
            user = match.group(1)
            if user not in user_activities:
                user_activities[user] = []
            user_activities[user].append(event)


if __name__ == "__main__":
    SecurityAnalyzer()
