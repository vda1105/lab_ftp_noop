# -*- coding: utf-8 -*-
import scapy.config
scapy.config.Conf.load_layers.remove("mspac")

from scapy.all import sniff, UDP
import time
import sys
import threading

# Tham số
EXPECTED_INTERVAL = 0.1  # Dựa trên INTERVAL trong encode.py
TIMEOUT = 0.3  # Thời gian tối đa để đợi gói tin
MIN_BITS = 80  # Số bit tối thiểu mong đợi (dựa trên độ dài thông điệp "b21dcat037")

timestamps = []
binary_data = ""
lock = threading.Lock()
stop_sniffing = threading.Event()
last_packet_time = None
sniffing_started = False

def packet_callback(packet):
    global timestamps, last_packet_time, sniffing_started
    if packet.haslayer(UDP) and packet[UDP].dport == 5006:
        now = time.time()
        sniffing_started = True
        timestamps.append(now)
        last_packet_time = now
        print "Nhận gói tin tại %f" % now

def sniff_packets():
    global sniffing_started
    print "Bắt đầu sniffing trên cổng 5006..."
    sniff(filter="udp and port 5006", prn=packet_callback, store=0, stop_filter=lambda p: stop_sniffing.is_set())
    print "Đã dừng sniffing."

def binary_to_text(binary_string):
    if len(binary_string) < 8:
        return "Chuỗi bit quá ngắn để giải mã."
    # Đảm bảo chuỗi bit đủ độ dài (bội số của 8)
    if len(binary_string) % 8 != 0:
        binary_string = binary_string + '0' * (8 - len(binary_string) % 8)
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    text = ''
    for char in chars:
        try:
            text += chr(int(char, 2))
        except ValueError:
            break
    return text

def wait_for_enter():
    global binary_data, last_packet_time, sniffing_started
    sys.stdout.write("\nNhấn Enter để giải mã: ")
    sys.stdout.flush()
    sys.stdin.readline().strip()
    stop_sniffing.set()

    if not sniffing_started:
        print "Không nhận được gói tin nào. Kiểm tra kết nối hoặc bên gửi."
        return

    # Xử lý các khoảng thời gian để xác định bit
    for i in range(len(timestamps) - 1):
        delta = timestamps[i + 1] - timestamps[i]
        if delta > EXPECTED_INTERVAL + 0.05:  # Cho phép sai số nhỏ
            num_missing = int(delta / EXPECTED_INTERVAL) - 1
            binary_data += '0' + '1' * num_missing
        else:
            binary_data += '0'

    # Thêm bit "1" nếu có gói bị mất ở cuối
    if last_packet_time:
        now = time.time()
        elapsed = now - last_packet_time
        if elapsed > EXPECTED_INTERVAL:
            num_missing = int(elapsed / EXPECTED_INTERVAL)
            binary_data += '1' * num_missing

    # Kiểm tra số bit
    print "\nSố bit nhận được:", len(binary_data)
    if len(binary_data) < MIN_BITS:
        print "Cảnh báo: Số bit nhận được quá ít, có thể không đủ để giải mã thông điệp đầy đủ."
    print "Chuỗi bit nhận được:", binary_data

    decoded_text = binary_to_text(binary_data)
    print "\nDecoded message:", decoded_text
    with open("result_lack.txt", "w") as f:
        f.write(decoded_text)

try:
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.setDaemon(True)
    sniff_thread.start()

    # Chờ trong thời gian tối đa để nhận đủ gói tin
    start_time = time.time()
    while not stop_sniffing.is_set():
        if last_packet_time and (time.time() - last_packet_time > TIMEOUT):
            print "Không nhận được gói tin mới trong %f giây, có thể bên gửi đã dừng." % TIMEOUT
            break
        if time.time() - start_time > 30:  # Thời gian tối đa 30 giây
            print "Hết thời gian chờ, dừng sniffing."
            break
        time.sleep(0.1)

    wait_for_enter()
    print "\nDừng sniffing. Kết quả đã lưu vào result_lack.txt"
except KeyboardInterrupt:
    stop_sniffing.set()
except Exception as e:
    print "Lỗi:", e
    stop_sniffing.set()
