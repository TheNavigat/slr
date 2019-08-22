from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

import dpkt
import socket
import struct

key = b'7\x98\xc1\xdf\x7f}\xea5?\\6\x17\tlT\xed\xa2a\x0fn\x87.(\x0c\xe4;*4\xda\x8fY\xc8'
keycs = AESGCM(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    client_ip = "2100::104"
    pkt.src = socket.inet_pton(socket.AF_INET6, client_ip)

    dst_ip = "2100::102"
    pkt.dst = socket.inet_pton(socket.AF_INET6, dst_ip)

    ci = struct.unpack(">I", pkt.all_extension_headers[0].data[2:6])[0]
    nonce = struct.unpack(">I", pkt.all_extension_headers[0].data[6:10])[0]
    noncep = struct.unpack(">I", pkt.all_extension_headers[0].data[10:14])[0]
    payload_signature = str(pkt.all_extension_headers[0].data[14:30])

    extension_header = bytes(keycs.decrypt(bytes(nonce), pkt.all_extension_headers[0].data[30:-87], ''))

    pkt.nxt = ord(extension_header[0])

    pkt.all_extension_headers = []
    pkt.extension_hdrs = []

    pkt.data = str(keycs.decrypt(bytes(noncep), pkt.data + payload_signature, ''))

    pkt.plen = len(pkt.data)

    higher_level_packet = None

    if pkt.nxt == 58:
        higher_level_packet = dpkt.icmp6.ICMP6(pkt.data)
    elif pkt.nxt == 6:
        higher_level_packet = dpkt.tcp.TCP(pkt.data)
    elif pkt.nxt == 17:
        higher_level_packet = dpkt.udp.UDP(pkt.data)

    higher_level_packet.sum = 0
    pkt.data = str(higher_level_packet)
    higher_level_packet.sum = update_checksum(pkt)
    pkt.data = higher_level_packet

    sockfd.sendto(bytes(pkt), ('::1', 0))

    packet.drop()


def ones_comp_add16(num1, num2):
    MOD = 2**16
    result = num1 + num2
    return result if result < MOD else (result + 1) % MOD


def update_checksum(ip_packet):
    x = 0

    for byte in entire_packet_to_four_bytes(ip_packet.src):
        x = ones_comp_add16(x, byte)

    for byte in entire_packet_to_four_bytes(ip_packet.dst):
        x = ones_comp_add16(x, byte)

    for byte in number_to_four_bytes(ip_packet.plen):
        x = ones_comp_add16(x, byte)

    x = ones_comp_add16(x, ip_packet.nxt)

    for pack in entire_packet_to_four_bytes(ip_packet.data):
        x = ones_comp_add16(x, pack)

    x = 65535 - x # One's complement
    return x


def split_into_four_bytes(number):
    x = []
    while(number > 0):
        remainder = number % (2**16)
        x.append(remainder)
        number /= 2**16

    return x


def entire_packet_to_four_bytes(packet):
    x = list(bytes(packet))

    y = x[0::2] # Even indices
    z = x[1::2] # Odd indices

    result = []

    for i in range(0, len(y)):
        r = ord(y[i]) << 8

        if(i < len(z)):
            r += ord(z[i])

        result.append(r)

    return result


def number_to_four_bytes(number):
    x = []

    while(number > 0):
        x.append(number % (2**16))
        number /= 2**16

    return x

nfqueue = NetfilterQueue()

#1 is the iptables rule queue number, modify is the callback function
nfqueue.bind(1, modify)

nfqueue.run()
