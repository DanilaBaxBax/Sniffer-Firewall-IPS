from scapy.all import send, IP, UDP
import random

def generate_traffic(target_ip, port, packet_count=1000):
    """
    Генерация большого объема UDP-пакетов для тестирования системы.
    
    :param target_ip: IP-адрес цели
    :param port: Целевой порт
    :param packet_count: Количество пакетов
    """
    for _ in range(packet_count):
        packet = IP(dst=target_ip) / UDP(dport=port) / bytes(random.randbytes(100))
        send(packet, verbose=False)

if __name__ == "__main__":
    target_ip = "192.168.1.9"  # Локальный IP
    port = 80  # Целевой порт
    packet_count = 1000  # Количество пакетов
    
    generate_traffic(target_ip, port, packet_count)
    print(f"Отправлено {packet_count} пакетов на {target_ip}:{port}")
