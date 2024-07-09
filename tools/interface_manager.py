import scapy.all as scapy
from typing import List


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
    non_loopback = [iface for iface in interfaces if not iface.startswith("lo")]
    if non_loopback:
        return non_loopback[0]

    # If only loopback is available, use it
    return interfaces[0]


def print_interface_info() -> str:
    """
    Print information about available network interfaces and the selected default.

    Returns:
        str: The name of the selected default interface.
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
