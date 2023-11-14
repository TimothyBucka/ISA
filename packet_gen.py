#!/usr/bin/python3

from scapy.all import *

# def send_dhcp_packet(message_type, transaction_id, client_mac):
#     # Create the DHCP packet
#     ethernet = Ether(dst="ff:ff:ff:ff:ff:ff")
#     ip = IP(src="0.0.0.0", dst="255.255.255.255")
#     udp = UDP(sport=68, dport=67)
#     bootp = BOOTP(chaddr=client_mac, xid=transaction_id)
#     dhcp = DHCP(options=[("message-type", message_type), "end"])

#     # Combine all the layers into a single packet
#     dhcp_packet = ethernet / ip / udp / bootp / dhcp

#     # Send the packet
#     sendp(dhcp_packet)

# # Send a DHCP Discover packet
# send_dhcp_packet("discover", 12345, "00:01:02:03:04:05")

# # Send a DHCP Offer packet
# send_dhcp_packet("offer", 12345, "00:01:02:03:04:05")

# # Send a DHCP Request packet
# send_dhcp_packet("request", 12345, "00:01:02:03:04:05")

# # Send a DHCP Acknowledgment packet
# send_dhcp_packet("ack", 12345, "00:01:02:03:04:05")

# # Send a DHCP Inform packet
# send_dhcp_packet("inform", 12345, "00:01:02:03:04:05")

# # Send a DHCP Lease Query packet
# send_dhcp_packet("lease_query", 12345, "00:01:02:03:04:05")



# # Create a DHCP Discover packet
# from ipaddress import IPv4Address

# # Starting IP address
# ip_start = IPv4Address('192.168.1.1')

# # Send 10 DHCP Ack packets with different IP addresses
# for i in range(20):
#     # Calculate the new IP address
#     ip_addr = ip_start + i

#     # Create a new DHCP Ack packet with the new IP address
#     dhcp_ack = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
#         BOOTP(op=2, xid=0x01020304, yiaddr=str(ip_addr)) / DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.255.0"), "end"])

#     # Send the packet
#     sendp(dhcp_ack, iface="eth0")

from ipaddress import IPv4Address

# Starting IP address
ip_start = IPv4Address('192.168.1.1')

# Send 10 pairs of DHCP Request and Ack packets with different IP addresses
for i in range(10):
    # Calculate the new IP address
    ip_addr = ip_start + i

    # Create a new DHCP Request packet with the new IP address
    dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
        BOOTP(op=1, xid=0x01020304 + i, ciaddr=str(ip_addr)) / DHCP(options=[("message-type", "request"), ("requested_addr", str(ip_addr)), "end"])

    # Send the Request packet
    sendp(dhcp_request, iface="eth0")

    # Create a new DHCP Ack packet with the same IP address
    dhcp_ack = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=67, dport=68) / \
        BOOTP(op=2, xid=0x01020304 + i, yiaddr=str(ip_addr)) / DHCP(options=[("message-type", "ack"), ("subnet_mask", "255.255.255.0"), "end"])

    # Send the Ack packet
    sendp(dhcp_ack, iface="eth0")
