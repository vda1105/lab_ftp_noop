# -*- coding: utf-8 -*-
from scapy.all import send, IP, UDP, Raw  # Thêm IP, UDP, Raw vào import
import time
import sys

if len(sys.argv) < 2:
    print "Usage: python encode.py <message>"
    sys.exit(1)

message = sys.argv[1]

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text) + '0'

binary_data = text_to_binary(message)
print "Chuỗi bit:", binary_data

DEST_IP = "172.20.0.2"
DEST_PORT = 5006
INTERVAL = 0.1

for bit in binary_data:
    if bit == '0':
        pkt = IP(dst=DEST_IP) / UDP(dport=DEST_PORT) / Raw(load="Audio packet")
        send(pkt, verbose=0)
        print "Gửi gói tin cho bit '0' tại %f" % time.time()
    else:
        print "Bỏ qua gói tin cho bit '1' tại %f" % time.time()
    time.sleep(INTERVAL)

print "Gửi thành công"
print "success"
