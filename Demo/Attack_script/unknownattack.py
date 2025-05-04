from scapy.all import IP, TCP, send
import time

def port_scan(target_ip, start_port=1, end_port=200, rate_per_second=100):
    """
    Посылает TCP SYN на последовательность портов,
    чтобы смоделировать порт-сканирование.
    """
    delay = 1.0 / rate_per_second
    for port in range(start_port, end_port+1):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags='S')
        send(pkt, verbose=False)
        time.sleep(delay)

if __name__ == "__main__":
    target = "192.168.1.9"
    print(f"Стартуем сканирование {target} портов 1–200 …")
    port_scan(target, 1, 200, rate_per_second=200)
    print("Готово.")
