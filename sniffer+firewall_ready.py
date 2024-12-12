from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Хранилище данных для графика
ip_actions = defaultdict(lambda: {"Allow": 0, "Deny": 0})

# Список заблокированных IP-адресов
blocked_ips = []

# Имя файла для сохранения логов
log_file = "packet_logs.csv"
sniffer_running = False
sniffer_thread = None



# Хранилище данных для статистики
ip_stats = defaultdict(lambda: {
    "in_bytes": 0, "out_bytes": 0,
    "in_pkts": 0, "out_pkts": 0,
    "tcp_flags": set(), "first_packet_time": None, "last_packet_time": None
})


# Инициализация файла логов с заголовками
def initialize_csv(file_name):
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "SRC_ADDR", "SRC_PORT", "DST_ADDR", "DST_PORT", "PROTOCOL", "IN_BYTES", "OUT_BYTES",
                         "IN_PKTS", "OUT_PKTS", "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS", "ACTION"])


# Получение строкового представления TCP флагов
def get_tcp_flags(flags):
    flags_str = []
    if flags & 0x02:
        flags_str.append("SYN")
    if flags & 0x10:
        flags_str.append("ACK")
    if flags & 0x01:
        flags_str.append("FIN")
    if flags & 0x04:
        flags_str.append("RST")
    if flags & 0x08:
        flags_str.append("PSH")
    if flags & 0x20:
        flags_str.append("URG")
    return ",".join(flags_str) if flags_str else "NONE"


# Проверка, является ли IP-адрес локальным
def is_local_ip(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("127.")


# Обработчик пакетов
def packet_handler(packet):
    # Получаем текущую дату и время
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    # Проверяем, есть ли IP слой в пакете
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else ''
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else ''

        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
        tcp_flags = get_tcp_flags(packet[TCP].flags) if TCP in packet else "NONE"
        packet_size = len(packet)

        # Определяем направление пакета
        if is_local_ip(dst_ip):  # Входящий трафик
            direction = "in"
            ip_data = ip_stats[dst_ip]
        elif is_local_ip(src_ip):  # Исходящий трафик
            direction = "out"
            ip_data = ip_stats[src_ip]
        else:
            # Если ни один из адресов не локальный, игнорируем пакет
            return
        
        # Обновляем статистику
        if direction == "in":
            ip_data["in_bytes"] += packet_size
            ip_data["in_pkts"] += 1
        else:
            ip_data["out_bytes"] += packet_size
            ip_data["out_pkts"] += 1

        if tcp_flags != "NONE":
            ip_data["tcp_flags"].add(tcp_flags)

        # Для первого пакета устанавливаем время
        if ip_data["first_packet_time"] is None:
            ip_data["first_packet_time"] = datetime.now()

        # Обновляем время последнего пакета
        ip_data["last_packet_time"] = datetime.now()

        # Рассчитываем продолжительность потока
        flow_duration_ms = 0
        if ip_data["first_packet_time"] and ip_data["last_packet_time"]:
            flow_duration_ms = (ip_data["last_packet_time"] - ip_data["first_packet_time"]).total_seconds() * 1000

        # Определяем действие: Allow или Deny
        action = "Deny" if src_ip in blocked_ips else "Allow"
        
        # Обновляем статистику действий для IP
        ip_actions[src_ip][action] += 1

        # Формируем строку для вывода
        log_message = (f"[{timestamp}] SRC_ADDR: {src_ip}, SRC_PORT: {src_port}, DST_ADDR: {dst_ip}, "
                       f"DST_PORT: {dst_port}, PROTOCOL: {protocol}, IN_BYTES: {ip_data['in_bytes']}, "
                       f"OUT_BYTES: {ip_data['out_bytes']}, IN_PKTS: {ip_data['in_pkts']}, OUT_PKTS: {ip_data['out_pkts']}, "
                       f"TCP_FLAGS: {','.join(ip_data['tcp_flags'])}, FLOW_DURATION_MILLISECONDS: {flow_duration_ms:.2f}, ACTION: {action}")
        print(log_message)

        # Сохранение данных в CSV
        try:
            with open(log_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                                 ip_data["in_bytes"], ip_data["out_bytes"], ip_data["in_pkts"],
                                 ip_data["out_pkts"], ",".join(ip_data["tcp_flags"]), flow_duration_ms, action])
        except Exception as e:
            print(f"Error writing to log file: {e}")



# Запуск сниффера
def start_sniffer():
    global sniffer_running, sniffer_thread
    if not sniffer_running:
        sniffer_running = True
        initialize_csv(log_file)  # Создаем/очищаем файл перед началом
        sniffer_thread = threading.Thread(target=sniff, kwargs={
            "filter": "ip",
            "prn": packet_handler,
            "store": False
        })
        sniffer_thread.daemon = True
        sniffer_thread.start()
        messagebox.showinfo("Sniffer", "Sniffer started.")


# Остановка сниффера
def stop_sniffer():
    global sniffer_running
    if sniffer_running:
        sniffer_running = False
        messagebox.showinfo("Sniffer", "Sniffer stopped.")


# Добавление правила
def add_rule(ip):
    if ip and ip not in blocked_ips:
        blocked_ips.append(ip)
        update_rules_list()
        messagebox.showinfo("Rule", f"IP {ip} added to deny list.")
        ip_entry.delete(0, tk.END)  # Очистка поля ввода после добавления
    elif ip in blocked_ips:
        messagebox.showwarning("Rule", f"IP {ip} is already in the deny list.")
        ip_entry.delete(0, tk.END)  # Очистка даже если IP уже в списке


# Удаление правила
def remove_rule(ip=None):
    if ip:  # Удаление по введенному адресу
        if ip in blocked_ips:
            blocked_ips.remove(ip)
            update_rules_list()
            messagebox.showinfo("Rule", f"IP {ip} removed from deny list.")
        else:
            messagebox.showwarning("Rule", f"IP {ip} not found in the deny list.")
    else:  # Удаление выбранного в списке
        selected_index = rules_listbox.curselection()  # Получаем индекс выбранного элемента
        if selected_index:
            selected_ip = rules_listbox.get(selected_index)  # Получаем IP из списка
            blocked_ips.remove(selected_ip)  # Удаляем IP из списка заблокированных
            update_rules_list()  # Обновляем графический список
            messagebox.showinfo("Rule", f"IP {selected_ip} removed from deny list.")
        else:
            messagebox.showwarning("Rule", "No IP selected to remove.")  # Если ничего не выбрано


# Обновление списка правил в интерфейсе
def update_rules_list():
    rules_listbox.delete(0, tk.END)
    for ip in blocked_ips:
        rules_listbox.insert(tk.END, ip)


# Открытие файла логов
def open_logs():
    file_path = filedialog.askopenfilename(
        title="Open Log File",
        filetypes=(("CSV Files", "*.csv"), ("All Files", "*.*")),
        initialfile=log_file
    )
    if file_path:
        try:
            log_window = tk.Toplevel(root)
            log_window.title("Log File")
            text_area = tk.Text(log_window, wrap="none", width=100, height=30)

            # Функция для обновления логов
            def update_logs():
                try:
                    with open(file_path, mode='r') as file:
                        logs = file.read()
                    text_area.configure(state="normal")
                    text_area.delete(1.0, tk.END)  # Очистка текстового поля
                    text_area.insert(tk.END, logs)  # Вставка новых логов
                    text_area.configure(state="disabled")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open log file: {e}")

                # Планируем следующее обновление через 10000 мс (10 секунда)
                log_window.after(10000, update_logs)

            # Первоначальное обновление логов
            update_logs()

            # Кнопка для обновления логов вручную
            refresh_button = ttk.Button(log_window, text="Refresh Logs", command=update_logs)
            refresh_button.pack(side="bottom", padx=10, pady=10)

            text_area.pack(fill="both", expand=True)

        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")


# Построение графика
def plot_graph():
    def update(frame):
        ax.clear()  # Очистка графика перед обновлением

        # Собираем данные для входящих пакетов
        ips = list(ip_actions.keys())
        deny_counts = [ip_actions[ip]["Deny"] for ip in ips]
        allow_counts = [ip_actions[ip]["Allow"] for ip in ips]

        # Построение графика
        x_indexes = range(len(ips))
        ax.bar(x_indexes, deny_counts, color="red", label="Deny")
        ax.bar(x_indexes, allow_counts, color="green", bottom=deny_counts, label="Allow")

        # Настройка осей и подписи
        ax.set_xticks(x_indexes)
        ax.set_xticklabels(ips, rotation=45, ha="right")  # Подписи оси X (IP-адреса)
        ax.set_ylabel("Incoming Packets")
        ax.set_title("Real-Time Incoming Packet Statistics")
        ax.legend()

    # Создание окна для графика
    graph_window = tk.Toplevel(root)
    graph_window.title("Real-Time Incoming Packet Statistics")

    fig, ax = plt.subplots(figsize=(10, 6))
    canvas = FigureCanvasTkAgg(fig, master=graph_window)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    # Анимация графика (обновление каждые 1000 мс)
    ani = FuncAnimation(fig, update, interval=1000)
    canvas.draw()


# Создание главного окна
root = tk.Tk()
root.title("Packet Sniffer GUI")
root.geometry("600x400")

# Кнопки для управления сниффером
frame_controls = ttk.Frame(root)
frame_controls.pack(pady=10, fill="x")

start_button = ttk.Button(frame_controls, text="Start Sniffer", command=start_sniffer)
start_button.pack(side="left", padx=5)

stop_button = ttk.Button(frame_controls, text="Stop Sniffer", command=stop_sniffer)
stop_button.pack(side="left", padx=5)

log_button = ttk.Button(frame_controls, text="Open Logs", command=open_logs)
log_button.pack(side="left", padx=5)

plot_button = ttk.Button(frame_controls, text="Show Graph", command=plot_graph)
plot_button.pack(side="left", padx=5)

# Фрейм для управления правилами
frame_rules = ttk.Frame(root)
frame_rules.pack(pady=10, fill="x")

ip_entry = ttk.Entry(frame_rules)
ip_entry.pack(side="left", padx=5, fill="x", expand=True)

add_button = ttk.Button(frame_rules, text="Add Rule", command=lambda: add_rule(ip_entry.get()))
add_button.pack(side="left", padx=5)

remove_button = ttk.Button(frame_rules, text="Remove Selected Rule", command=lambda: remove_rule())
remove_button.pack(side="left", padx=5)

# Список текущих правил
rules_listbox = tk.Listbox(root, height=10)
rules_listbox.pack(pady=10, fill="both", expand=True)

# Обновляем список правил при запуске
update_rules_list()

# Запуск GUI
root.mainloop()
