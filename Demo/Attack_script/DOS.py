from scapy.all import send, IP, UDP
import random

def generate_traffic(target_ip, port, packet_count=1000):
    
    for _ in range(packet_count):
        packet = IP(dst=target_ip) / UDP(dport=port) / bytes(random.randbytes(100))
        send(packet, verbose=False)

if __name__ == "__main__":
    target_ip = "192.168.1.9"  
    port = 80  
    packet_count = 1000  
    
    generate_traffic(target_ip, port, packet_count)
    print(f"Отправлено {packet_count} пакетов на {target_ip}:{port}")
