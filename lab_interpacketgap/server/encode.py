from scapy.all import send, IP, UDP
import time
import sys

if len(sys.argv) < 2:
    print("Usage: python test.py <message>")
    sys.exit(1)
message = sys.argv[1]

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

binary_data = text_to_binary(message)
binary_data = binary_data + '0'
print(binary_data)
DEST_IP = "172.20.0.2"  
DEST_PORT = 5005  

DELAY_0 = 0.1 
DELAY_1 = 0.5  

for bit in binary_data:
    pkt = IP(dst=DEST_IP) / UDP(dport=DEST_PORT)
    send(pkt, verbose=False)
    time.sleep(DELAY_1 if bit == '1' else DELAY_0)

print("success")

