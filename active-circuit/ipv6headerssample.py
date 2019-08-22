from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

import dpkt
import random
import socket
import struct

key = b'7\x98\xc1\xdf\x7f}\xea5?\\6\x17\tlT\xed\xa2a\x0fn\x87.(\x0c\xe4;*4\xda\x8fY\xc8'
keycs = AESGCM(key)

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

    src_ip = socket.inet_pton(socket.AF_INET6, '0:0:0:0:0:0:0:0')
    pkt.src = src_ip

    dst_ip = socket.inet_pton(socket.AF_INET6, '2100::103')
    pkt.dst = dst_ip

    noncecs = random.randint(0, 4294967295)
    nonceca = random.randint(0, 4294967295)

    noncecsp = random.randint(0, 4294967295)
    noncecap = random.randint(0, 4294967295)

    # AES always outputs 16 bytes (signature) + size of input data
    encrypted_payload = keycs.encrypt(bytes(noncecsp), bytes(pkt.data), '')
    encrypted_payload_signature = encrypted_payload[-16:]
    encrypted_payload = encrypted_payload[:-16]

    # chr is fine because pkt.nxt is one byte
    encrypted_cs = keycs.encrypt(bytes(noncecs), chr(pkt.nxt), '')

    # First byte (\x7b) is the circuit identifier
    header_cs = bytes(
        struct.pack(">I", 123)
        + struct.pack(">I", noncecs)
        + struct.pack(">I", noncecsp)
        + encrypted_payload_signature
        + encrypted_cs
    )

    encrypted_payload = keyca.encrypt(bytes(noncecap), bytes(encrypted_payload), '')

    encrypted_payload_signature = encrypted_payload[-16:]
    encrypted_payload = encrypted_payload[:-16]

    encrypted_ca = keyca.encrypt(bytes(nonceca), bytes(header_cs), '')

    # First byte (\x7b) is the circuit identifier
    header_ca = bytes(
        struct.pack(">I", 123)
        + struct.pack(">I", nonceca)
        + struct.pack(">I", noncecap)
        + encrypted_payload_signature
        + encrypted_ca
    )

    # Should end up having length 132
    encrypted = pad_extension_header(header_ca)

    pkt.nxt = 60
    pkt.p = pkt.nxt

    # Total length should be 136 bytes
    pkt.all_extension_headers = ['\x63\x10\x1e\x84' + encrypted]
    pkt.data = encrypted_payload
    pkt.plen = len(pkt.data) + 136

    sockfd.sendto(bytes(pkt), ('2100::103', 0))

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
