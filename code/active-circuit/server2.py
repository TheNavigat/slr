from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

import dpkt
import random
import socket
import struct

key = b'7\x98\xc1\xdf\x7f}\xea5?\\6\x17\tlT\xed\xa2a\x0fn\x87.(\x0c\xe4;*4\xda\x8fY\xc8'
keysc = AESGCM(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    noncesc = random.randint(0, 4294967295)
    noncescp = random.randint(0, 4294967295)

    src_ip = socket.inet_pton(socket.AF_INET6, '0:0:0:0:0:0:0:0')
    pkt.src = src_ip

    dst_ip = socket.inet_pton(socket.AF_INET6, '2100::104')
    pkt.dst = dst_ip

    encrypted = keysc.encrypt(bytes(noncesc), bytes(chr(pkt.nxt)), '')

    encrypted_payload = keysc.encrypt(bytes(noncescp), bytes(pkt.data), '')
    encrypted_payload_signature = encrypted_payload[-16:]
    encrypted_payload = encrypted_payload[:-16]

    header_ca = bytes(
        struct.pack(">I", 123)
        + struct.pack(">I", noncesc)
        + struct.pack(">I", noncescp)
        + encrypted_payload_signature
        + encrypted
    )

    extension_header = pad_extension_header(header_ca)

    pkt.nxt = 60
    pkt.p = 60

    pkt.all_extension_headers = ['\x63\x10\x1e\x84' + extension_header]
    pkt.extension_hdrs = []

    pkt.data = encrypted_payload

    pkt.plen = len(pkt.data) + 136

    sockfd.sendto(bytes(pkt), ('2100::104', 0))

    packet.drop() #accept the packet


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
nfqueue.bind(2, modify)

nfqueue.run()
