from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from netfilterqueue import NetfilterQueue

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import dpkt
import socket
import struct

key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAu5CGUJIk41oMpDYzZpIS1YV+zWje9JhP71pYmFc6bnXysYQ5\nL25FVQv4NJoBmXWFWMr+gadokWmKZBUoqlTZgrh/42pY8Pz+WJXrNJa5wyE6rv9H\noS9MGq5sS4nvt48uKzMoHfn7zrwFSifXKYZPvv+Fq6+fCRZh28s5Kkv2PM1xbu1z\njheC0GzPwEltqJP54/axI2W4CvWraG3SLiwyYT3aVpSLWRInoqhHDfMQfRSsDHaU\nKTT01vrSPif55FCUrGbP+4rX7c/n6huG/DJNsBkMGnJG9A1JO0fz8YWisgdmNI8+\n8rIcgYRGmCLhoZq868Sn9TAX5FgdjY/3SYbDBQIDAQABAoIBAQCTB9Iias274yUx\nvMNCTpOxCbrC7siH2LYgnSQCF67YVGFxQoNJaRm0d3OUWH2UfImRd19W55KTGra/\nic6c53KyhErMTNt33frMGomMafMowW2tLLRL6DWyXLTL6k8eB4Fbn/h8ty/reXx0\nCxMhnAX7ZXa1hTAYAZGoqIAhZfaa5eHPT6BomXABnyV4JeMi37PJj6xCD0/yyyH1\nsTM8Z4rYpA5vlNNbiTopet3xeTuyqLz9GJs6Tjf2uki2ALUcyvdRM/10azO7yjbF\n5J/p/cPcSRTR+l2DGB7lYogksEoF7A/jJOBTXyknNAOq9kRT1kB1RtAnvNhyQzIX\n1g51tplBAoGBANseqNGw9lpbpFGnKFhNwmJfaVd7Xdi7o+qSNRBcmT1L0hEQ3ga9\n0qK4bQE1VkntLTeVKednajVnIeHFNtWPDBLdRTfjQSl5T3myvQfdsHIP6J0DmaFO\ntAADfexMhrZZnrUzwm24h/gxrRBd1n8d9LEmRTupksQ/FZAG8ZsyIZ89AoGBANsi\nOjWH49VacmjfspetlVA71PzX1yXZfo6nOcJRpRl1ijUbj1Yh7/2w5ClpPCsH/mst\nq/gn/MlRjyIK441yxuS2Tx26iwnhIf0ZpKYsYbfG/hwEKfF9p88nvJFmd1SZmNQq\n5zXS98fGSEXzDQOEPmMEb/+P6E+dHAWh7M/HhW9pAoGBANeVF6WPhSGrbkTDwGb4\nwloE42ClyNR28LPV+41IfaAYG+qcfMWHN1jPOLfqoSYEyusXv+2jCpTWDjjRzrxY\njBl3SCXPWgoTB4WFvIOjsnjWfBcXNqzFAUXOKbM2K4f3LrW64f0Pg/9F6K7klCfm\n8hrku1MS6IpaQr28hzMZJIlFAoGAAjvLFBiafeY6HE+LZnhieTri5ODeVIhu/c0+\njXh/kk7cZcYuI9act51B9hoYfufJ9BW3FwRxUyv9pX8u6pYs6M/i5o6sNCGTUx0b\nzIXPSSxCEs8IDmoVd8sT5PeCZ95Y7HCzgpzv4Z1nxy6/BzYl3KSC77vrxkP3sScB\nXuzNs2ECgYEAqK5RvkdGBb9OwB1tU4zojLVKXBixPWbZEPIQPRd10wd0FDxx/bWF\nou8NBbe6wRmBnOYAgCEgCnSwP+U79Jj2xbMi1NkoneWl15W2f/2H/7JxV+SjtXDb\n/pWvJXs4DwOQz+17bzxRbU+zObDFMwiIMFEPPoaAVJswH4HMoEIuwNE=\n-----END RSA PRIVATE KEY-----"
asymmetrickeya = RSA.importKey(key)

sockfd = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Inform the Operating System that the script crafts the IP header itself
sockfd.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, True)

def modify(packet):
    pkt = dpkt.ip6.IP6(packet.get_payload())

    if is_icmp_neighbour_message(pkt):
        packet.accept()
        return

    aes_key_text = pkt.data[:256]
    aes_key_text = asymmetrickeya.decrypt(aes_key_text)
    nonce = struct.unpack(">I", pkt.data[256:260])[0]
    ecdhe = pkt.data[260:292]
    ci = struct.unpack(">I", pkt.data[292:296])[0]

    aes_key = AESGCM(aes_key_text)

    decrypted_block = bytes(aes_key.decrypt(bytes(nonce), pkt.data[296:], ''))

    ip_s = decrypted_block[:16]

    ecdhe_ac = X25519PrivateKey.generate()
    signature = sign(ecdhe_ac.public_key().public_bytes(), asymmetrickeya)

    pkt.data = decrypted_block[16:] + ecdhe_ac.public_key().public_bytes() + signature
    pkt.plen = len(pkt.data)

    pkt.dst = ip_s

    sockfd.sendto(bytes(pkt), (socket.inet_ntop(socket.AF_INET6, ip_s), 0))

    packet.drop()


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
