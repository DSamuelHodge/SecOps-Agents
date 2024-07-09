from scapy.all import IP, TCP, UDP, ICMP, Ether, RandIP, RandMAC, wrpcap
import random


def generate_packet():
    # Randomly choose between TCP, UDP, and ICMP
    proto = random.choice([TCP, UDP, ICMP])

    if proto == ICMP:
        return (
            Ether(src=RandMAC(), dst=RandMAC())
            / IP(src=RandIP(), dst=RandIP())
            / ICMP()
        )
    elif proto == UDP:
        return (
            Ether(src=RandMAC(), dst=RandMAC())
            / IP(src=RandIP(), dst=RandIP())
            / UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 1023))
        )
    else:  # TCP
        return (
            Ether(src=RandMAC(), dst=RandMAC())
            / IP(src=RandIP(), dst=RandIP())
            / TCP(sport=random.randint(1024, 65535), dport=random.randint(1, 1023))
        )


# Generate a list of 100 random packets
packets = [generate_packet() for _ in range(100)]

# Write the packets to a PCAP file
output_file = "data/generated_traffic.pcap"
wrpcap(output_file, packets)

print(f"Generated PCAP file: {output_file}")
