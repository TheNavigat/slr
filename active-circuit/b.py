from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

import dpkt
import random
import socket
import struct

key = b'\xef\x20\x0b\xdd\x60\x65\x4e\x48\xc4\x3d\x1d\x19\x9f\x3f\x79\x23\x4f\xdb\xe2\x8e\xfb\x54\xa7\xe9\x88\x71\x47\xed\xbf\xce\x01\x20'
keybc = AESGCM(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    noncebc = random.randint(0, 4294967295)
    noncebcp = random.randint(0, 4294967295)

    encrypted_payload = keybc.encrypt(bytes(noncebcp), bytes(pkt.data), '')
    encrypted_payload_signature = encrypted_payload[-16:]
    encrypted_payload = encrypted_payload[:-16]

    header_sb = pkt.all_extension_headers[0].data[2:-87]

    encrypted = keybc.encrypt(bytes(noncebc), bytes(header_sb), '')

    header_bc = bytes(
        struct.pack(">I", 123)
        + struct.pack(">I", noncebc)
        + struct.pack(">I", noncebcp)
        + encrypted_payload_signature
        + encrypted
    )

    header_bc = pad_extension_header(header_bc)

    pkt.all_extension_headers = ['\x63\x10\x1e\x84' + header_bc]

    dst_ip = "2100::101"

    pkt.dst = socket.inet_pton(socket.AF_INET6, dst_ip)
    pkt.data = encrypted_payload

    sockfd.sendto(bytes(pkt), (dst_ip, 0))

    packet.drop()


def is_icmp_neighbour_message(ip_packet):
    if ip_packet.nxt != 58:
        return False

    icmp_packet = ip_packet.data

    if icmp_packet.type == 135 or icmp_packet.type == 136:
        return True

    return False


def pad_extension_header(ext_header):
    padding_length = 132 - len(ext_header)
    return ext_header + ('z' * padding_length)


nfqueue = NetfilterQueue()

#1 is the iptables rule queue number, modify is the callback function
nfqueue.bind(1, modify)

nfqueue.run()
