import scapy.all as scapy
import nmap
from typing import List, Dict, Any

def get_available_interfaces() -> List[str]:
    """
    Get a list of available network interfaces.
    
    Returns:
        List[str]: A list of interface names.
    """
    return scapy.get_if_list()

def select_default_interface() -> str:
    """
    Select a default network interface.
    
    Prefers non-loopback interfaces if available.
    
    Returns:
        str: The name of the selected interface.
    
    Raises:
        RuntimeError: If no network interfaces are found.
    """
    interfaces = get_available_interfaces()
    if not interfaces:
        raise RuntimeError("No network interfaces found")
    
    # Prefer non-loopback interfaces
    non_loopback = [iface for iface in interfaces if not iface.startswith('lo')]
    if non_loopback:
        return non_loopback[0]
    
    # If only loopback is available, use it
    return interfaces[0]

def print_interface_info():
    """
    Print information about available network interfaces and the selected default.
    """
    interfaces = get_available_interfaces()
    print("Available network interfaces:", interfaces)
    
    try:
        default_interface = select_default_interface()
        print(f"Selected default interface: {default_interface}")
        return default_interface
    except RuntimeError as e:
        print(f"Error: {e}")
        return None

def scan_network(target: str) -> Dict[str, Any]:
    """
    Perform a network scan using python-nmap.
    
    Args:
        target (str): The target IP address or range to scan.
    
    Returns:
        Dict[str, Any]: A dictionary containing scan results.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sn')  # -sn for ping scan
    
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            'status': nm[host].state(),
            'hostname': nm[host].hostname()
        }
    
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