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
from matplotlib.figure import Figure
import re
import pickle
from sklearn.preprocessing import LabelEncoder
import pandas as pd
from sklearn.preprocessing import StandardScaler
import time
import os
import tensorflow as tf
import numpy as np

# Хранилище данных для графика
ip_actions = defaultdict(lambda: {"Allow": 0, "Deny": 0})

# Список заблокированных IP-адресов
blocked_ips = []

#Файл с правилами
rules_file = "rules.txt"

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
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("127.") or ip.startswith("2.56.") or ip.startswith("8.8.") or ip.startswith("0.0.")


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
    global sniffer_running, sniffer_thread
    if sniffer_running:
        sniffer_running = False
        messagebox.showinfo("Sniffer", "Sniffer stopped.")


# Чтение правил из файла
def load_rules_from_file():
    global blocked_ips
    if os.path.exists(rules_file):
        with open(rules_file, "r") as file:
            blocked_ips = [line.strip() for line in file if line.strip()]
    update_rules_list()

# Запись правил в файл
def save_rules_to_file():
    with open(rules_file, "w") as file:
        file.write("\n".join(blocked_ips))

# Функция для проверки валидности IP-адреса
def is_valid_ip(ip):
    # Регулярное выражение для проверки правильности формата IP-адреса
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) is not None and all(0 <= int(part) <= 255 for part in ip.split('.'))

# Обновление функции добавления правила
# Добавление правила
def add_rule(ip):
    if not ip:
        messagebox.showwarning("Rule", "IP address cannot be empty.")
        return

    if not is_valid_ip(ip):
        messagebox.showwarning("Rule", f"{ip} is not a valid IP address.")
        ip_entry.delete(0, tk.END)
        return

    if ip not in blocked_ips:
        blocked_ips.append(ip)
        save_rules_to_file()  # Сохраняем обновленный список в файл
        update_rules_list()  # Обновляем интерфейс
        messagebox.showinfo("Rule", f"IP {ip} added to deny list.")
        ip_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Rule", f"IP {ip} is already in the deny list.")
        ip_entry.delete(0, tk.END)


# Удаление правила
def remove_rule(ip=None):
    if ip:
        if ip in blocked_ips:
            blocked_ips.remove(ip)
            save_rules_to_file()  # Сохраняем обновленный список в файл
            update_rules_list()  # Обновляем интерфейс
            messagebox.showinfo("Rule", f"IP {ip} removed from deny list.")
        else:
            messagebox.showwarning("Rule", f"IP {ip} not found in the deny list.")
    else:
        selected_index = rules_listbox.curselection()
        if selected_index:
            selected_ip = rules_listbox.get(selected_index)
            blocked_ips.remove(selected_ip)
            save_rules_to_file()  # Сохраняем обновленный список в файл
            update_rules_list()  # Обновляем интерфейс
            messagebox.showinfo("Rule", f"IP {selected_ip} removed from deny list.")
        else:
            messagebox.showwarning("Rule", "No IP selected to remove.")


# Обновление списка правил в интерфейсе
def update_rules_list():
    rules_listbox.delete(0, tk.END)
    for ip in blocked_ips:
        rules_listbox.insert(tk.END, ip)

# Отслеживание изменений в файле
def watch_rules_file():
    global blocked_ips
    try:
        if os.path.exists(rules_file):
            with open(rules_file, "r") as file:
                new_ips = [line.strip() for line in file if line.strip()]
                if new_ips != blocked_ips:
                    blocked_ips = new_ips
                    update_rules_list()
    except Exception as e:
        print(f"Error watching file: {e}")
    root.after(1000, watch_rules_file)

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
#def plot_graph():
 #   def update(frame):
  #      ax.clear()  # Очистка графика перед обновлением
#
 #       # Собираем данные для входящих пакетов
  #      ips = list(ip_actions.keys())
   #     deny_counts = [ip_actions[ip]["Deny"] for ip in ips]
    #    allow_counts = [ip_actions[ip]["Allow"] for ip in ips]
#
 #       # Построение графика
  #      x_indexes = range(len(ips))
   #     ax.bar(x_indexes, deny_counts, color="red", label="Deny")
    #    ax.bar(x_indexes, allow_counts, color="green", bottom=deny_counts, label="Allow")
#
 #       # Настройка осей и подписи
  #      ax.set_xticks(x_indexes)
   #     ax.set_xticklabels(ips, rotation=45, ha="right")  # Подписи оси X (IP-адреса)
    #    ax.set_ylabel("Incoming Packets")
     #   ax.set_title("Real-Time Incoming Packet Statistics")
      #  ax.legend()

    # Создание окна для графика
 #   graph_window = tk.Toplevel(root)
  #  graph_window.title("Real-Time Incoming Packet Statistics")

 #   fig, ax = plt.subplots(figsize=(10, 6))
 #   canvas = FigureCanvasTkAgg(fig, master=graph_window)
 #   canvas.get_tk_widget().pack(fill="both", expand=True)

  #  ani = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)
   # canvas.draw()

def read_csv_and_update_stats():
    """
    Считывает CSV-файл и обновляет глобальную статистику ip_actions.
    """
    try:
        # Проверяем, существует ли файл и не пустой ли он
        if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
            return
    except Exception as e:
        print('Лог-файл отсутствует или пуст. Ожидание новых данных..."')               
    try:
        # Читаем данные из CSV
        data = pd.read_csv(log_file)

        # Проверяем, что столбцы SRC_ADDR и Action существуют
        if "SRC_ADDR" not in data.columns or "Action" not in data.columns:
            print("Ошибка: отсутствуют нужные столбцы в CSV")
            return

        # Обновляем статистику
        global ip_actions
        ip_actions.clear()
        for _, row in data.iterrows():
            src_ip = row["SRC_ADDR"]
            action = row["Action"]
            if action in ["Allow", "Deny"]:
                ip_actions[src_ip][action] += 1
    except Exception as e:
        print(f"Ошибка чтения CSV: {e}")

def plot_graph():
    # Создание нового окна для графика
    graph_window = tk.Toplevel(root)
    graph_window.title("Real-Time Incoming Packet Statistics")

    # Создание объекта Figure для графика
    fig, ax = Figure(figsize=(8, 6)), None

    def update(frame):
        """
        Функция для обновления графика.
        """
        nonlocal ax
        # Обновляем статистику из CSV
        read_csv_and_update_stats()

        # Очищаем ось и подготавливаем данные
        fig.clear()
        ax = fig.add_subplot(111)

        ips = list(ip_actions.keys())
        allow_values = [ip_actions[ip]["Allow"] for ip in ips]
        deny_values = [ip_actions[ip]["Deny"] for ip in ips]

        x = range(len(ips))

        # Построение столбцов
        ax.bar(x, allow_values, color="green", label="Allow")
        ax.bar(x, deny_values, bottom=allow_values, color="red", label="Deny")
        ax.set_xticks(x)
        ax.set_xticklabels(ips, rotation=45, ha="right")
        ax.legend()
        ax.set_title("Количество пакетов (Allow vs Deny)")
        ax.set_ylabel("Количество пакетов")
        ax.set_xlabel("IP-адреса")

    # Создание объекта Canvas для отображения графика в окне
    canvas = FigureCanvasTkAgg(fig, master=graph_window)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Настройка анимации
    ani = FuncAnimation(fig, update, interval=1000)

    # Запуск графика
    canvas.draw()    
#########################################################################################IPS MODULE#####################################################################################

# Инициализация переменных
model = None
deep_model = None
is_analyzing = False

def load_model():
    """Загрузка модели нейронной сети из файла .pkl"""
    global model
    model_path = filedialog.askopenfilename(filetypes=[("Pickle files", "*.pkl")])
    if model_path:
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            messagebox.showinfo("Успех", "Модель успешно загружена.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить модель: {e}")



def analyze_logs():
    if model is None:
        messagebox.showerror("Ошибка", "Сначала загрузите модель.")
        return
    
    # Выбор файла логов для анализа
    log_file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if not log_file:
        return
    
    try:
        # Загрузка логов
        logs_df = pd.read_csv(log_file)
        
        # Проверяем, что все необходимые столбцы присутствуют
        required_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']
        for col in required_columns:
            if col not in logs_df.columns:
                messagebox.showerror("Ошибка", f"Столбец '{col}' отсутствует в данных.")
                return
        
        # Выбираем только необходимые столбцы
        data = logs_df[required_columns]
        logs_df['Prediction'] = model.predict(data)
        
        # Сохранение нового датасета в файл CSV
        output_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if output_file:
            logs_df.to_csv(output_file, index=False)
            messagebox.showinfo("Успех", "Анализ завершен, файл сохранен.")
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить файл.")
    
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка при анализе логов: {e}")

# Function for real-time analysis
def real_time_analysis():
    if model is None:
        messagebox.showerror("Ошибка", "Сначала загрузите модель.")
        return

    # Continuously analyze new log entries
    while True:
        log_file = 'packet_logs.csv'  # Or you can use filedialog to select it
        try:
            # Загрузка логов
            logs_df = pd.read_csv(log_file)
            
            # Проверяем, что все необходимые столбцы присутствуют
            required_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS', 'SRC_ADDR']
            for col in required_columns:
                if col not in logs_df.columns:
                    messagebox.showerror("Ошибка", f"Столбец '{col}' отсутствует в данных.")
                    return

            # Прогнозируем атаки
            data = logs_df[required_columns[:-1]]  # Exclude SRC_ADDR for prediction
            logs_df['Prediction'] = model.predict(data)
            
            # Обновление столбца Action на 'deny', если есть атака
            logs_df['ACTION'] = logs_df['Prediction'].apply(lambda x: 'deny' if x == 1 else 'allow')
            
            # Чтение существующих правил из файла rules.txt
            with open('rules.txt', 'r') as file:
                existing_ips = set(file.read().splitlines())

            # Обработка каждого SRC_ADDR, если Action = 'deny'
            for index, row in logs_df.iterrows():
                if row['ACTION'] == 'deny' and row['SRC_ADDR'] not in existing_ips:
                    # Добавляем новый IP в rules.txt
                    with open('rules.txt', 'a') as file:
                        file.write(f"{row['SRC_ADDR']}\n")
                    existing_ips.add(row['SRC_ADDR'])  # Обновляем set для предотвращения повторов

            # Сохранение изменений в packet_logs.csv
            logs_df.to_csv(log_file, index=False)

            # Задержка перед следующей проверкой
            time.sleep(5)  # Можете изменить на нужное вам время

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при анализе логов: {e}")
            break  # Если ошибка, остановим выполнение


def deep_load_model():
    """Загрузка модели нейронной сети из файла .h5"""
    global deep_model
    deep_model_path = filedialog.askopenfilename(filetypes=[("H5 files", "*.h5")])
    if deep_model_path:
        try:
            # Загрузка модели в формате h5
            deep_model = tf.keras.models.load_model(deep_model_path)
            messagebox.showinfo("Успех", "Модель успешно загружена.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить модель: {e}")

def deep_analyze_logs():
    """Анализ логов с использованием загруженной модели."""
    if deep_model is None:
        messagebox.showerror("Ошибка", "Сначала загрузите модель.")
        return
    
    # Выбор файла логов для анализа
    log_file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if not log_file:
        return
    
    try:
        # Загрузка логов
        logs_df = pd.read_csv(log_file)
        
        # Проверяем, что все необходимые столбцы присутствуют
        required_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']
        for col in required_columns:
            if col not in logs_df.columns:
                messagebox.showerror("Ошибка", f"Столбец '{col}' отсутствует в данных.")
                return
        
        # Ожидаемые оригинальные метки
        original_labels = ['Benign', 'dos', 'injection', 'ddos', 'scanning', 'password', 'mitm', 'xss', 'backdoor', 'ransomware']

        # Создаем LabelEncoder с уже заданными метками
        label_encoder = LabelEncoder()
        label_encoder.fit(original_labels)  # Используем ваши метки для обучения LabelEncoder

        # Разделение данных на признаки (X) для предсказания
        X = logs_df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']]

        # Стандартизация данных (очень важно для нейронных сетей)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Используем модель для предсказания
        y_pred = deep_model.predict(X_scaled)

        # Преобразуем вероятности в классы
        y_pred_classes = y_pred.argmax(axis=1)  # Получаем предсказанные классы

        # Декодируем предсказанные классы обратно в исходные метки
        y_pred_labels = label_encoder.inverse_transform(y_pred_classes)

        # Добавляем предсказания в DataFrame
        logs_df['Prediction'] = y_pred_labels
        
        # Сохранение нового датасета в файл CSV
        output_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if output_file:
            logs_df.to_csv(output_file, index=False)
            messagebox.showinfo("Успех", "Анализ завершен, файл сохранен.")
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить файл.")
    
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка при анализе логов: {e}")

# Глобальная переменная для хранения данных
traffic_count = defaultdict(lambda: defaultdict(int))
ip_addresses = []
traffic_types = ['Benign', 'dos', 'injection', 'ddos', 'scanning', 'password', 'mitm', 'xss', 'backdoor', 'ransomware']
traffic_data = {traffic_type: [] for traffic_type in traffic_types}

def deep_plot_traffic_realtime():
    """Построение обновляющегося в реальном времени столбчатого графика запросов по IP с учетом типа трафика."""
    if deep_model is None:
        messagebox.showerror("Ошибка", "Сначала загрузите модель.")
        return

    # Выбор файла для анализа
    log_file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if not log_file:
        return

    try:
        # Загрузка данных после анализа
        logs_df = pd.read_csv(log_file)

        # Проверка наличия необходимых столбцов
        if 'Prediction' not in logs_df.columns or 'SRC_ADDR' not in logs_df.columns:
            messagebox.showerror("Ошибка", "Отсутствуют необходимые столбцы для построения графика.")
            return

        # Заполнение данных для графика
        global traffic_count, ip_addresses, traffic_data
        traffic_count = defaultdict(lambda: defaultdict(int))

        for _, row in logs_df.iterrows():
            ip = row['SRC_ADDR']
            traffic_type = row['Prediction']
            traffic_count[ip][traffic_type] += 1

        # Получаем список IP и обновляем данные для графика
        ip_addresses = list(traffic_count.keys())
        for traffic_type in traffic_types:
            traffic_data[traffic_type] = [traffic_count[ip].get(traffic_type, 0) for ip in ip_addresses]

        # Создание графика
        fig, ax = plt.subplots(figsize=(15, 8))  # Увеличиваем размер графика
        colors = plt.cm.get_cmap("tab10", len(traffic_types))  # 10 цветов

        def update(frame):
            """Функция обновления графика."""
            ax.clear()
            width = 0.8 / len(traffic_types)  # Ширина одного столбца
            x_indices = np.arange(len(ip_addresses))  # Индексы для IP-адресов

            for idx, traffic_type in enumerate(traffic_types):
                # Сдвиг столбцов для каждого типа трафика
                x_positions = x_indices + (idx - len(traffic_types) / 2) * width
                ax.bar(
                    x_positions,
                    traffic_data[traffic_type],
                    width=width,
                    label=traffic_type,
                    color=colors(idx),
                )

            ax.set_xlabel('IP Address')
            ax.set_ylabel('Количество запросов')
            ax.set_title('Количество запросов по SRC_ADDR для различных типов трафика')
            ax.set_xticks(x_indices)
            ax.set_xticklabels(ip_addresses, rotation=45, ha='right', fontsize=10)  # Угол поворота и размер шрифта
            ax.legend(title="Тип трафика", loc='upper left', bbox_to_anchor=(1.05, 1))  # Легенда за пределами графика
            ax.grid(True)
            fig.tight_layout()  # Автоматическая подгонка содержимого графика

        ani = FuncAnimation(fig, update, frames=10, interval=1000, blit=False)

        # Вставка графика в Tkinter
        global canvas
        if 'canvas' in globals() and canvas:
            canvas.get_tk_widget().destroy()  # Удаляем старый график, если он существует

        canvas = FigureCanvasTkAgg(fig, master=ips_window)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=10, fill='both', expand=True)

           # Динамическое изменение размера окна
        ips_window.update_idletasks()  # Обновляем размеры окна
        graph_width = canvas.get_tk_widget().winfo_reqwidth()
        graph_height = canvas.get_tk_widget().winfo_reqheight()
        new_width = max(1400, graph_width + 50)  # Увеличиваем минимальную ширину окна
        new_height = max(900, graph_height + 150)  # Увеличиваем минимальную высоту окна
        ips_window.geometry(f"{new_width}x{new_height}")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка при построении графика: {e}")


def open_ips_window():
    """Открывает новое окно для работы с IPS."""
    global ips_window, real_time_analysis_button
    ips_window = tk.Toplevel()
    ips_window.title("IPS Система")
    ips_window.geometry("1920x1080")  # Увеличиваем размер окна

    # Фрейм для верхних кнопок
    button_frame_top = tk.Frame(ips_window)
    button_frame_top.pack(pady=10, fill='x')

    # Верхние кнопки
    load_deep_model_button = tk.Button(button_frame_top, text="Загрузить глубокую модель", command=deep_load_model)
    load_deep_model_button.pack(side="left", padx=5)

    deep_analysis_button = tk.Button(button_frame_top, text="Глубокий анализ", command=deep_analyze_logs)
    deep_analysis_button.pack(side="left", padx=5)

    analyze_button = tk.Button(button_frame_top, text="Построить график", command=deep_plot_traffic_realtime)
    analyze_button.pack(side="left", padx=5)

    # Фрейм для нижних кнопок
    button_frame_bottom = tk.Frame(ips_window)
    button_frame_bottom.pack(pady=10, fill='x', side='bottom')

    # Нижние кнопки
    load_model_button = tk.Button(button_frame_bottom, text="Загрузить модель", command=load_model)
    load_model_button.pack(side="left", padx=5)

    analyze_logs_button = tk.Button(button_frame_bottom, text="Провести анализ", command=analyze_logs)
    analyze_logs_button.pack(side="left", padx=5)
    
    # Включить/выключить анализ в реальном времени
    real_time_analysis_button = tk.Button(button_frame_bottom, text="Включить анализ в реальном времени", command=lambda: threading.Thread(target=real_time_analysis, daemon=True).start())
    real_time_analysis_button.pack(side="left", padx=5)


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

# Кнопка для открытия окна IPS
ips_button = ttk.Button(frame_controls, text= "IPS ", command=open_ips_window)
ips_button.pack(side="left", padx=5)

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

# Загрузка правил из файла и запуск отслеживания изменений
load_rules_from_file()
watch_rules_file()

# Обновляем список правил при запуске
update_rules_list()

# Запуск GUI
root.mainloop()

