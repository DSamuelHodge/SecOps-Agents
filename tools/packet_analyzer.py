# This class analyzes captured network packets using Scapy library.
# It provides methods to store packets, analyze protocols, source/destination IPs,
# HTTP methods, and DNS queries. It also generates a report summarizing the analysis.

import asyncio
from scapy.all import AsyncSniffer
from collections import defaultdict
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from typing import List, Dict, Any
from .interface_manager import select_default_interface, print_interface_info
from .network_scanner import scan_network, print_scan_results


class PacketAnalyzer:
    def __init__(self):
        self.packets: List = []
        self.protocol_counter: Dict[str, int] = defaultdict(int)
        self.ip_counter: Dict[str, int] = defaultdict(int)
        self.http_methods: Dict[str, int] = defaultdict(int)
        self.dns_queries: Dict[str, int] = defaultdict(int)

    def packet_callback(self, packet):
        self.packets.append(packet)
        if len(self.packets) % 100 == 0:
            print(f"Captured {len(self.packets)} packets...")

    def analyze_packets(self):
        for packet in self.packets:
            self._analyze_single_packet(packet)

    def _analyze_single_packet(self, packet):
        if IP in packet:
            self._analyze_ip_packet(packet)

    def _analyze_ip_packet(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        self.ip_counter[src_ip] += 1
        self.ip_counter[dst_ip] += 1

        if TCP in packet:
            self._analyze_tcp_packet(packet)
        elif UDP in packet:
            self.protocol_counter["UDP"] += 1

        if HTTP in packet:
            self._analyze_http_packet(packet)
        if DNS in packet:
            self._analyze_dns_packet(packet)

    def _analyze_tcp_packet(self, packet):
        self.protocol_counter["TCP"] += 1
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            self.protocol_counter["HTTP"] += 1
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
            self.protocol_counter["HTTPS"] += 1

    def _analyze_http_packet(self, packet):
        if hasattr(packet[HTTP], "Method"):
            self.http_methods[packet[HTTP].Method.decode()] += 1

    def _analyze_dns_packet(self, packet):
        if packet[DNS].qr == 0 and packet[DNS].qd:
            query = packet[DNS].qd.qname.decode("utf-8")
            self.dns_queries[query] += 1

    def generate_report(self) -> str:
        packet_count = len(self.packets)
        report = [
            "Network Traffic Analysis Report",
            "=" * 40,
            f"Total packets captured: {packet_count}\n",
        ]

        report.extend(self._generate_protocol_distribution(packet_count))
        report.extend(self._generate_top_ip_addresses())
        report.extend(self._generate_http_methods())
        report.extend(self._generate_dns_queries())

        return "\n".join(report)

    def _generate_protocol_distribution(self, packet_count: int) -> List[str]:
        report = ["Protocol Distribution:"]
        for protocol, count in self.protocol_counter.items():
            report.append(f"  {protocol}: {count} ({count/packet_count*100:.2f}%)")
        return report

    def _generate_top_ip_addresses(self) -> List[str]:
        report = ["\nTop 5 IP Addresses:"]
        for ip, count in sorted(
            self.ip_counter.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            report.append(f"  {ip}: {count} packets")
        return report

    def _generate_http_methods(self) -> List[str]:
        if not self.http_methods:
            return []
        report = ["\nHTTP Methods:"]
        for method, count in self.http_methods.items():
            report.append(f"  {method}: {count}")
        return report

    def _generate_dns_queries(self) -> List[str]:
        if not self.dns_queries:
            return []
        report = ["\nTop 5 DNS Queries:"]
        for query, count in sorted(
            self.dns_queries.items(), key=lambda x: x[1], reverse=True
        )[:5]:
            report.append(f"  {query}: {count}")
        return report


async def run_network_analysis(
    duration: int = 10, interface: str = None
) -> Dict[str, Any]:
    if interface is None:
        interface = select_default_interface()

    print(f"Capturing packets on interface {interface} for {duration} seconds...")

    analyzer = PacketAnalyzer()

    capture_thread = AsyncSniffer(
        iface=interface, prn=analyzer.packet_callback, store=False
    )
    capture_thread.start()

    await asyncio.sleep(duration)
    capture_thread.stop()

    print(f"Capture complete. Analyzing {len(analyzer.packets)} packets...")

    analyzer.analyze_packets()
    return {"report": analyzer.generate_report(), "packet_count": len(analyzer.packets)}


if __name__ == "__main__":

    async def main():
        default_interface = print_interface_info()
        if default_interface:
            try:
                # Perform network scan
                print("Performing network scan...")
                scan_results = scan_network(
                    "192.168.1.0/24"
                )  # Adjust this to your network range
                print_scan_results(scan_results)

                # Run packet analysis
                analysis_result = await run_network_analysis(
                    duration=30, interface=default_interface
                )
                print(analysis_result["report"])
            except RuntimeError as e:
                print(f"Error: {e}")
        else:
            print("No suitable network interface found. Exiting.")

        await main()
