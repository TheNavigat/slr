from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from netfilterqueue import NetfilterQueue

import dpkt
import random
import socket
import struct
import sys
import time

keya_text = b'4p\xf8ipfD(\x99\xbb\x1d\xa2k\xeb\xaf\x05\xf0\x16\xdfGK\xb8V\xd4\xf3\x17?]S\xa0{B'
keya = AESGCM(keya_text)

keys_text = b'\xe5Q\x92r\xe2\xfc\xde!\xa5|\x19\xb5\x99\x00\xc0\\\xe8\x0fN\xff:\xefi\x0bg\xb7\xe3\x87M\xf1`\xb1'
keys = AESGCM(keys_text)

keyb_text = b'}fd>@\xb21y\xd4\x88\xe0C\x9a\xab]\xd5cEL\xc5\xbc\xd9-YG\xc8\x8d\x08^r\xb9\xad'
keyb = AESGCM(keyb_text)

pubkey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5CGUJIk41oMpDYzZpIS\n1YV+zWje9JhP71pYmFc6bnXysYQ5L25FVQv4NJoBmXWFWMr+gadokWmKZBUoqlTZ\ngrh/42pY8Pz+WJXrNJa5wyE6rv9HoS9MGq5sS4nvt48uKzMoHfn7zrwFSifXKYZP\nvv+Fq6+fCRZh28s5Kkv2PM1xbu1zjheC0GzPwEltqJP54/axI2W4CvWraG3SLiwy\nYT3aVpSLWRInoqhHDfMQfRSsDHaUKTT01vrSPif55FCUrGbP+4rX7c/n6huG/DJN\nsBkMGnJG9A1JO0fz8YWisgdmNI8+8rIcgYRGmCLhoZq868Sn9TAX5FgdjY/3SYbD\nBQIDAQAB\n-----END PUBLIC KEY-----'
asymmetrickeya = RSA.importKey(pubkey)

pubkey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjggW52Zpc3rQY1sQUmju\nOqKkmkQkPFdftVj1z3yspbtC2VjrOmu8MY99tR25aPU+t7TjIlVCyJbq9f6Gpt8w\n13tBqk/zi3igc+pfjs4pqyNSWcQlV2a+3l68Zp8UGWaSIKoabs6jnM+8/u0EzlAq\nwpG/jHrc/js/PuCO4ge+6oMZ9zcn/iEc1WAGHI649VeqK/yUOpPfzqsfZE52WkrH\nBLr6sxp8E/uXA8uAeF1+p0qiL7EjrF2lvDEmA7JrTLaqnwFCfRyY4IhGNYf8dAB1\n3gKbzoeE5KBLZgVEFeWuuJIuPligdlCiKwJwHm7DSS/ujoKmwx2Z3O1DgSv+65K6\nZQIDAQAB\n-----END PUBLIC KEY-----'
asymmetrickeys = RSA.importKey(pubkey)

pubkey = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAruJ2zpbGhjr+LS1eiz2f\nMvBcOcv55vWfND+/Alz9bpuDD2xMMDVvKO9LTRjEwMzyJi6i5GBpcsDblDbu3LmN\nc2iGWW9FDmOBYDAWBQtr3UO61KMBIT2iT7NcQqhPZYFy+lQgAYH6WjASlYLq/4GP\n2qKXw1MDA8NAntFq3W3aHNWlIN2wddRWGUa6d/fl1lLKT4L6DsFftuY7GQfzrBOt\nzPBxCVv8w4mU2r+Ixergy6Qjz96GXPiQvze2ZaRxW5+Ob+P8TW+JOufyEzQB3r4w\nddjUjoHiwzj72w80oDMUS3BtiVuJg0GVkJlVmKD9SuBZdIkhAQqF9WKAhy9ouJxD\nIwIDAQAB\n-----END PUBLIC KEY-----'
asymmetrickeyb = RSA.importKey(pubkey)

ecdhe_cb = X25519PrivateKey.generate()
ecdhe_cs = X25519PrivateKey.generate()
ecdhe_ca = X25519PrivateKey.generate()

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

initial_time = 0
final_time = 0

# Run 1000 times
counter = 1000

def run():
    ip6_packet = dpkt.ip6.IP6()

    ip6_packet.src = socket.inet_pton(socket.AF_INET6, '0:0:0:0:0:0:0:0')
    ip6_packet.dst = socket.inet_pton(socket.AF_INET6, '2100::103')

    # Prepare Header C
    ci_c = random.randint(0, 4294967295)
    header_c = struct.pack(">I", ci_c)

    # Prepare Header B
    header_b = asymmetrickeyb.encrypt(keyb_text, 0)[0]

    nonce_b = random.randint(0, 4294967295)
    header_b += struct.pack(">I", nonce_b)

    header_b += ecdhe_cb.public_key().public_bytes()

    ci_b = random.randint(0, 4294967295)
    header_b += struct.pack(">I", ci_b)

    ip_c = socket.inet_pton(socket.AF_INET6, '2100::101')

    encrypted_blob = keyb.encrypt(bytes(nonce_b), bytes(ip_c) + bytes(header_c), '')

    header_b += encrypted_blob

    # Prepare IP Option S
    header_s = asymmetrickeys.encrypt(keys_text, 0)[0]

    nonce_s = random.randint(0, 4294967295)
    header_s += struct.pack(">I", nonce_s)

    header_s += ecdhe_cs.public_key().public_bytes()

    ci_s = random.randint(0, 4294967295)
    header_s += struct.pack(">I", ci_s)

    ip_b = socket.inet_pton(socket.AF_INET6, '2100::104')

    encrypted_blob = keys.encrypt(bytes(nonce_s), bytes(ip_b) + bytes(header_b), '')

    header_s += encrypted_blob

    # Prepare IP Option A
    header_a = asymmetrickeya.encrypt(keya_text, 0)[0]

    nonce_a = random.randint(0, 4294967295)
    header_a += struct.pack(">I", nonce_a)

    header_a += ecdhe_ca.public_key().public_bytes()

    ci_a = random.randint(0, 4294967295)
    header_a += struct.pack(">I", ci_a)

    ip_s = socket.inet_pton(socket.AF_INET6, '2100::102')

    encrypted_blob = keya.encrypt(bytes(nonce_a), bytes(ip_s) + bytes(header_s), '')

    header_a += encrypted_blob

    ip6_packet.nxt = 99
    ip6_packet.p = 99
    ip6_packet.all_extension_headers = []
    ip6_packet.extension_hdrs = []
    ip6_packet.data = header_a
    ip6_packet.plen = len(ip6_packet.data)

    sockfd.sendto(bytes(ip6_packet), ('2100::103', 0))

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    ci = struct.unpack(">I", pkt.data[:4])[0]

    # --- Header 2
    header_2 = pkt.data[4:]

    derived_key = parse_header_2_block(header_2, asymmetrickeyb, ecdhe_cb)
    nonce = struct.unpack(">I", header_2[288:292])[0]
    header_2 = bytes(derived_key.decrypt(bytes(nonce), header_2[292:], ''))

    derived_key = parse_header_2_block(header_2, asymmetrickeys, ecdhe_cs)
    nonce = struct.unpack(">I", header_2[288:292])[0]
    header_2 = bytes(derived_key.decrypt(bytes(nonce), header_2[292:], ''))

    derived_key = parse_header_2_block(header_2, asymmetrickeya, ecdhe_ca)

    packet.drop()

    global counter
    global initial_time

    final_time = time.time()

    print(final_time - initial_time)

    sys.stdout.flush()

    if counter > 0:
        counter -= 1
        print(counter)
        initial_time = time.time()
        run()

def parse_header_2_block(header_2, asymm_key, symm_key):
    ecdhe = header_2[:288]

    if not verify_signature(asymm_key, ecdhe):
        raise Exception("Signature failure")

    ecdhe = ecdhe[:32]

    shared_key = symm_key.exchange(X25519PublicKey.from_public_bytes(ecdhe))

    derived_key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        info=None,
        salt=None,
        backend=default_backend()
    ).derive(shared_key)

    derived_key = AESGCM(derived_key)

    return derived_key

def verify_signature(key, text):
    msg = text[:32]

    h = SHA512.new(msg)

    signature = text[32:]

    try:
        PKCS1_v1_5.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def is_icmp_neighbour_message(ip_packet):
    if ip_packet.nxt != 58:
        return False

    icmp_packet = ip_packet.data

    if icmp_packet.type == 135 or icmp_packet.type == 136:
        return True

    return False

nfqueue = NetfilterQueue()

# 2 is the iptables rule queue number, modify is the callback function
nfqueue.bind(2, modify)

initial_time = time.time()

run()

nfqueue.run()
