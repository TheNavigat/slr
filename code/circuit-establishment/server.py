from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from netfilterqueue import NetfilterQueue

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import dpkt
import random
import socket
import struct

key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAjggW52Zpc3rQY1sQUmjuOqKkmkQkPFdftVj1z3yspbtC2Vjr\nOmu8MY99tR25aPU+t7TjIlVCyJbq9f6Gpt8w13tBqk/zi3igc+pfjs4pqyNSWcQl\nV2a+3l68Zp8UGWaSIKoabs6jnM+8/u0EzlAqwpG/jHrc/js/PuCO4ge+6oMZ9zcn\n/iEc1WAGHI649VeqK/yUOpPfzqsfZE52WkrHBLr6sxp8E/uXA8uAeF1+p0qiL7Ej\nrF2lvDEmA7JrTLaqnwFCfRyY4IhGNYf8dAB13gKbzoeE5KBLZgVEFeWuuJIuPlig\ndlCiKwJwHm7DSS/ujoKmwx2Z3O1DgSv+65K6ZQIDAQABAoIBAFH+85IVuq0zatjh\nOrQI5fet688vpae8XYGpYQevF1D6oeYugmaQye3mxBDqnx6r7tBJupMYm9yH3A+2\nKHBwC5drDgbP729GbYNd/FrKRJ4LX0B5j4E8zNY95RBtqEHdyGDZMzdjTmt6NscJ\neKvO9lCrqeTlDW4sMCARrgtpo1tpBhwHNcJLOUQndrTgeu1f+f383QXBY15v6dPk\nQyh+RrNHX/lfyQ9n8J96rgq9c9FFnjEiafqAynGvYqjl6ZSzCU+eu50H85DeyPKU\nyDFgfl40RnIDZvRJs7cYshVgbEIiFoF/WfXmw2HXR+MUXPZ+9bKfsQb/WYfOo/k2\nDp9/t4ECgYEAtx22FhKwX2IARvyYIL4nprwdcEsgX5Je3mV7M4mpBW37NA++MkTf\naSB/ETmxP5l8f4EgcLL1PkP3M8HJYp/HUJHIsnviTWRKnAPw+21ZFMardnv+pPvW\n6SneH5Qm4sXmoF3Etg3DZafF3gmXbyZFJQbCDjru+PJNXKnsVH/RsEUCgYEAxpAm\nP5oQKzI8x5nCwMzkD2LqUW8bUN+H81IMlYbkAMLl8UYW+p2pm0t7mS3UD86o7oCh\ny+27G6oYNSV7RN0bNdkRDY92ocooh0OVREEMZpLoVnapGjWNQJaBmVhvIHs5Qvpd\nZakCM78NYoTqRhc2TAUKMcMNb8rseELu0vJi06ECgYBooVJ0xFMA/VdZOGWYd+7i\nJ6TOkC68TT9l5iiCZ0srrg8WTVSJFq9tO0M/zW5I/+OSW2701lypKl6qtTTj5JYX\npGVADudc/0xeXyYoE/ANngNFHU6AaOIAsoqYEqgxdZD02v9WYwDeKgI2f9aGjSB/\nKqBhTy1TE+g+ZV2DXtGq3QKBgQCnpB5WxljuT1zXXC78HkBR6T5RgI+8aOzb9qLf\nP2KSbfo7COTvtFr03Pa+Ld4DdoRT0NBJXy4Avkvv2vRHALIvdVObcktDb21mPh3w\n4UZ594AnN8mvchUOucMzV2GDN+XxcXWXFejhDWVcj0FH6eMSrZKczsQyZU3efwwp\nlzDu4QKBgGLXTyXhzOr1WIZEkZX0W7j/aOaDphdWQ9feRtKz2/AAJnp153T8nlY+\nt332eUk2uHzjlj502MqlF79I098rLQkxlQyQl6eOA++3/+rRJWNlz64oigy2heLm\nlR2Izj2qwCVMGLW2OJukseE0rpasFefCc+s01C2Vz3M15iJNmTWK\n-----END RSA PRIVATE KEY-----'
asymmetrickeys = RSA.importKey(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    aes_key_text = pkt.data[:256]
    aes_key_text = asymmetrickeys.decrypt(aes_key_text)
    nonce = struct.unpack(">I", pkt.data[256:260])[0]
    public_ecdhe_key = pkt.data[260:292]
    ci = struct.unpack(">I", pkt.data[292:296])[0]

    aes_key = AESGCM(aes_key_text)

    decrypted_block = bytes(aes_key.decrypt(bytes(nonce), pkt.data[296:-288], ''))

    ip_b = decrypted_block[:16]

    # --- Header 2

    header_2 = pkt.data[-288:]

    ecdhe = X25519PrivateKey.generate()

    shared_key = ecdhe.exchange(X25519PublicKey.from_public_bytes(public_ecdhe_key))

    derived_key = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        info=None,
        salt=None,
        backend=default_backend()
    ).derive(shared_key)

    key = AESGCM(derived_key)

    nonce = random.randint(0, 4294967295)

    encrypted_header = key.encrypt(bytes(nonce), header_2, '')

    signature = sign(ecdhe.public_key().public_bytes(), asymmetrickeys)

    header_2 = ecdhe.public_key().public_bytes() + signature + struct.pack(">I", nonce) + encrypted_header

    # Finalize packet

    pkt.data = decrypted_block[16:] + header_2
    pkt.plen = len(pkt.data)

    pkt.dst = ip_b

    sockfd.sendto(bytes(pkt), (socket.inet_ntop(socket.AF_INET6, ip_b), 0))

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

def is_icmp_neighbour_message(ip_packet):
    if ip_packet.nxt != 58:
        return False

    icmp_packet = ip_packet.data

    if icmp_packet.type == 135 or icmp_packet.type == 136:
        return True

    return False

def sign(message, priv_key):
    signer = PKCS1_v1_5.new(priv_key)
    digest = SHA512.new()
    digest.update(message)
    return signer.sign(digest)

nfqueue = NetfilterQueue()

# 1 is the iptables rule queue number, modify is the callback function
nfqueue.bind(1, modify)

nfqueue.run()
