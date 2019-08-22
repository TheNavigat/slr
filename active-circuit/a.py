from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

import dpkt
import socket
import struct

key = b'.\xb4\x19\x839J"ys\nSvQ\x16$\xfb\xa0\xeb4w\x83\xf8{\x8bN\x93ii\x9b&\xa2\xca'
keyca = AESGCM(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    dst_ip = "2100::102"

    pkt.dst = socket.inet_pton(socket.AF_INET6, dst_ip)

    ci = struct.unpack(">I", pkt.all_extension_headers[0].data[2:6])[0]
    nonce = struct.unpack(">I", pkt.all_extension_headers[0].data[6:10])[0]
    noncep = struct.unpack(">I", pkt.all_extension_headers[0].data[10:14])[0]
    payload_signature = str(pkt.all_extension_headers[0].data[14:30])

    extension_header = bytes(keyca.decrypt(bytes(nonce), pkt.all_extension_headers[0].data[30:-43], ''))

    pkt.all_extension_headers = ['\x63\x10\x1e\x84' + pad_extension_header(extension_header)]

    pkt.data = str(keyca.decrypt(bytes(noncep), pkt.data + payload_signature, ''))

    sockfd.sendto(bytes(pkt), (dst_ip, 0))

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
    ext_header += ('z' * padding_length)
    return ext_header

nfqueue = NetfilterQueue()

#1 is the iptables rule queue number, modify is the callback function
nfqueue.bind(1, modify)

nfqueue.run()
