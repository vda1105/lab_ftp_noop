from scapy.all import sniff
import time
import sys
import threading

DELAY_THRESHOLD = 0.3 

timestamps = []
binary_data = ""
lock = threading.Lock()
stop_sniffing = threading.Event()

def packet_callback(packet):
    global timestamps, binary_data
    
    now = time.time()
    
    if timestamps:
        delta = now - timestamps[-1]
        bit = '1' if delta > DELAY_THRESHOLD else '0'
        with lock:
            binary_data += bit
        sys.stdout.write(bit)
        sys.stdout.flush()
    
    timestamps.append(now)

def binary_to_text(binary_string):
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    text = ''.join(chr(int(char, 2)) for char in chars if len(char) == 8)
    return text

def wait_for_enter():
    global binary_data
    sys.stdout.write("\nPress Enter to decode message: ")
    sys.stdout.flush()
    sys.stdin.readline().strip()
    stop_sniffing.set()  # Dừng luồng sniffing
    
    with lock:
        decoded_text = binary_to_text(binary_data)
        print("\nDecoded message: ", decoded_text)
        
        # Lưu vào file result.txt
        with open("result.txt", "w", encoding="utf-8") as f:
            f.write(decoded_text)

def start_sniffing():
    sniff(filter="udp and port 5005", prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing.is_set())

try:
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    wait_for_enter()
    print("\nSniffing stopped. Output saved to result.txt")
except KeyboardInterrupt:
    print("\nExiting...")

