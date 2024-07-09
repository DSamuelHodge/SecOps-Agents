import nmap
from typing import Dict, Any


def scan_network(target: str) -> Dict[str, Any]:
    """
    Perform a network scan using python-nmap.

    Args:
        target (str): The target IP address or range to scan.

    Returns:
        Dict[str, Any]: A dictionary containing scan results.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sn")  # -sn for ping scan

    results = {}
    for host in nm.all_hosts():
        results[host] = {"status": nm[host].state(), "hostname": nm[host].hostname()}

    return results


def print_scan_results(results: Dict[str, Any]):
    """
    Print the results of a network scan.

    Args:
        results (Dict[str, Any]): The scan results to print.
    """
    print("\nNetwork Scan Results:")
    for host, info in results.items():
        print(f"Host: {host}")
        print(f"  Status: {info['status']}")
        print(f"  Hostname: {info['hostname']}")
        print()
