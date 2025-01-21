import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Устанавливаем таймаут на 0.5 секунды
            if s.connect_ex((host, port)) == 0:
                print(f"[+] Port {port} is open")
            else:
                pass  # Порт закрыт
    except Exception as e:
        print(f"[-] Error scanning port {port}: {e}")

def scan_ports(host, start_port, end_port, max_threads=100):
    print(f"Scanning {host} from port {start_port} to {end_port}...")
    with ThreadPoolExecutor(max_threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, host, port)

if __name__ == "__main__":
    target_host = input("Enter the target host (e.g., 127.0.0.1): ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    max_threads = int(input("Enter the maximum number of threads (default 100): ") or 100)
    num_cycles = int(input("Enter the number of scanning cycles: "))

    for cycle in range(1, num_cycles + 1):
        print(f"\nStarting scan cycle {cycle}/{num_cycles}...")
        scan_ports(target_host, start_port, end_port, max_threads)
        print(f"Cycle {cycle} completed.\n")
