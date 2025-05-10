from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Toplevel, Button
from tkinter import simpledialog
import threading
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.backend_bases import MouseEvent
from matplotlib.widgets import RectangleSelector 
from matplotlib.figure import Figure
import re
import pickle
from sklearn.preprocessing import LabelEncoder
import pandas as pd
from sklearn.preprocessing import StandardScaler
import time
import os
#import tensorflow as tf
import numpy as np
from colorama import Fore, Style

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
        writer.writerow([
            "Timestamp", "SRC_ADDR", "SRC_PORT", "DST_ADDR", "DST_PORT", "PROTOCOL",
            "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
            "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS", "ACTION"
        ])
    

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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else ''
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else ''

        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "OTHER"
        tcp_flags = get_tcp_flags(packet[TCP].flags) if TCP in packet else "NONE"
        packet_size = len(packet)

        if is_local_ip(dst_ip):
            direction = "in"
            ip_data = ip_stats[dst_ip]
        elif is_local_ip(src_ip):
            direction = "out"
            ip_data = ip_stats[src_ip]
        else:
            return

        if direction == "in":
            ip_data["in_bytes"] += packet_size
            ip_data["in_pkts"] += 1
        else:
            ip_data["out_bytes"] += packet_size
            ip_data["out_pkts"] += 1

        if tcp_flags != "NONE":
            ip_data["tcp_flags"].add(tcp_flags)

        if ip_data["first_packet_time"] is None:
            ip_data["first_packet_time"] = datetime.now()
        ip_data["last_packet_time"] = datetime.now()

        flow_duration_ms = (
            ip_data["last_packet_time"] - ip_data["first_packet_time"]
        ).total_seconds() * 1000

        action = "Deny" if src_ip in blocked_ips else "Allow"
        ip_actions[src_ip][action] += 1

        # Формируем строку
        log_message = (
            f"[{timestamp}] SRC_ADDR: {src_ip}, SRC_PORT: {src_port}, DST_ADDR: {dst_ip}, "
            f"DST_PORT: {dst_port}, PROTOCOL: {protocol}, IN_BYTES: {ip_data['in_bytes']}, "
            f"OUT_BYTES: {ip_data['out_bytes']}, IN_PKTS: {ip_data['in_pkts']}, OUT_PKTS: {ip_data['out_pkts']}, "
            f"TCP_FLAGS: {','.join(ip_data['tcp_flags'])}, FLOW_DURATION_MILLISECONDS: {flow_duration_ms:.2f}, ACTION: {action}"
        )

        # Цветной вывод
        #if action == "Deny":
         #   print(Fore.RED + log_message + Style.RESET_ALL)
        #else:
         #   print(Fore.GREEN + log_message + Style.RESET_ALL)

        try:
            with open(log_file, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                    ip_data["in_bytes"], ip_data["out_bytes"], ip_data["in_pkts"],
                    ip_data["out_pkts"], ",".join(ip_data["tcp_flags"]),
                    flow_duration_ms, action
                ])
        except Exception as e:
            print(f"Ошибка при записи в лог-файл: {e}")



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
            blocked_ips = [line.strip().split()[0] for line in file if line.strip()]  # Убираем deny
    update_rules_list()

# Запись правил в файл
def save_rules_to_file():
    with open(rules_file, "w") as file:
        file.write("\n".join(f"{ip} deny" for ip in blocked_ips))  # Добавляем deny

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


# Обновление списка правил в интерфейсе с добавлением действия deny
def update_rules_list():
    rules_listbox.delete(0, tk.END)
    for ip in blocked_ips:
        # Убедимся, что не дублируем 'deny'
        if ip.strip().endswith("deny"):
            rules_listbox.insert(tk.END, ip.strip())
        else:
            rules_listbox.insert(tk.END, f"{ip.strip()} deny")


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
    graph_window = tk.Toplevel(root)
    graph_window.title("Real-Time Incoming Packet Statistics")

    fig, ax = Figure(figsize=(10, 6)), None
    stats_cache = {}  # Кэш для хранения allow/deny по IP

    def update(frame):
        nonlocal ax, stats_cache
        fig.clear()
        ax = fig.add_subplot(111)

        try:
            df = pd.read_csv(log_file)

            if 'SRC_ADDR' not in df.columns or 'ACTION' not in df.columns:
                return

            df['ACTION'] = df['ACTION'].str.lower()
            allow_counts = df[df['ACTION'] == 'allow']['SRC_ADDR'].value_counts()
            deny_counts  = df[df['ACTION'] == 'deny']['SRC_ADDR'].value_counts()

            all_ips = sorted(set(allow_counts.index) | set(deny_counts.index))
            allow_vals = [allow_counts.get(ip, 0) for ip in all_ips]
            deny_vals  = [deny_counts.get(ip, 0) for ip in all_ips]

            # Обновим кэш статистики
            stats_cache = {
                ip: {"allow": allow_counts.get(ip, 0), "deny": deny_counts.get(ip, 0)}
                for ip in all_ips
            }

            x = range(len(all_ips))
            ax.bar(x, allow_vals, color="green", label="Allow")
            ax.bar(x, deny_vals, bottom=allow_vals, color="red", label="Deny")

            ax.set_xticks(x)
            ax.set_xticklabels(all_ips, rotation=45, ha="right")
            ax.set_xlabel("IP-адрес")
            ax.set_ylabel("Количество пакетов")
            ax.set_title("Allow vs Deny по IP")
            ax.legend()
            ax.grid(True)
        except Exception as e:
            print(f"[Graph error] {e}")

    def on_click(event):
        if event.inaxes != ax:
            return
        x_pos = event.xdata
        if x_pos is None:
            return
        idx = int(round(x_pos))
        try:
            ip = ax.get_xticklabels()[idx].get_text()
            stats = stats_cache.get(ip, {"allow": 0, "deny": 0})
            messagebox.showinfo(
                "Информация об IP",
                f"IP: {ip}\nAllow: {stats['allow']} пакетов\nDeny: {stats['deny']} пакетов"
            )
        except Exception as e:
            print(f"[Click error] {e}")

    canvas = FigureCanvasTkAgg(fig, master=graph_window)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    ani = FuncAnimation(fig, update, interval=1000)
    canvas.mpl_connect("button_press_event", on_click)
    canvas.draw()



# Очистка правил
def clear_rules():
    with open("rules.txt", "w") as file:
        file.truncate()  # Очищает содержимое файла        
#########################################################################################IPS MODULE#####################################################################################

# Инициализация переменных
model = None
deep_model = None
is_analyzing = False
attack_type_model = None

# main.py

import pickle
import pandas as pd
import os
import tkinter as tk
from tkinter import messagebox
# ... все ваши остальные импорты ...

class FakeDoSUnknownNet:
    """
    Объединённая модель:
      - >port_threshold уникальных портов/сек → 'unknown attack'
      - elif пакетов/сек > packet_threshold → 'dos'
      - else → 'benign'
    """
    def __init__(self, packet_threshold=500, port_threshold=50):
        self.packet_threshold = packet_threshold
        self.port_threshold   = port_threshold
        self.fitted = True
        self.labels = ['benign', 'dos', 'unknown attack']

    def predict(self, X: pd.DataFrame) -> pd.Series:
        if not {'Timestamp','SRC_ADDR','DST_PORT'}.issubset(X.columns):
            raise ValueError("Нужны колонки 'Timestamp','SRC_ADDR','DST_PORT'")
        df = X.copy()
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Second']    = df['Timestamp'].dt.floor('s')

        counts = (
            df.groupby(['SRC_ADDR','Second'])
              .size()
              .reset_index(name='Count')
        )
        scans = (
            df.groupby(['SRC_ADDR','Second'])['DST_PORT']
              .nunique()
              .reset_index(name='UniquePorts')
        )

        df = df.merge(counts, on=['SRC_ADDR','Second'], how='left')
        df = df.merge(scans, on=['SRC_ADDR','Second'], how='left')

        def classify(row):
            c = row['Count'] or 0
            p = row['UniquePorts'] or 0
            if p > self.port_threshold:
                return 'unknown attack'
            if c > self.packet_threshold:
                return 'dos'
            return 'benign'

        return df.apply(classify, axis=1)

# Теперь безопасно грузим модель:
def load_model():
    global model
    model_path = 'fake_dos_unknown_model.pkl'
    try:
        with open(model_path, 'rb') as f:
            loaded = pickle.load(f)
            model = loaded.get("model") if isinstance(loaded, dict) else loaded
        if not hasattr(model, 'predict'):
            messagebox.showerror("Ошибка", "Невалидная модель.")
            model = None
            return
        messagebox.showinfo("Успех", "Модель определения атак успешно загружена")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить модель: {e}")
        model = None

        

def load_another_model():
    global model
    model_path = filedialog.askopenfilename(filetypes=[("Pickle files", "*.pkl")])

    if model_path:
        try:
            with open(model_path, 'rb') as f:
                loaded = pickle.load(f)
                model = loaded.get("model") if isinstance(loaded, dict) else loaded

            if not hasattr(model, 'predict'):
                messagebox.showerror("Ошибка", "Загруженный объект не является моделью.")
                return

            messagebox.showinfo("Успех", f"Модель успешно загружена: {model_path}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить модель: {e}")

# ────────────────────────────────────────────────────────────────────────────────
# Подключение Random Forest-модели
rf_model = None

def load_rf_model():
    """Загрузка Random Forest-модели по умолчанию из файла random_forest_model.pkl"""
    global rf_model
    model_path = 'random_forest_model-2.pkl'  # убедитесь, что файл именно так называется
    try:
        with open(model_path, 'rb') as f:
            loaded = pickle.load(f)
        # если загрузилось словарём — пытаемся взять loaded["model"], иначе — сам объект
        rf_model = loaded.get("model", loaded) if isinstance(loaded, dict) else loaded
        if not hasattr(rf_model, "predict"):
            raise ValueError("В pkl-файле нет объекта с методом predict")
        messagebox.showinfo("Успех", f"RF-модель успешно загружена: {model_path}")
    except Exception as e:
        rf_model = None
        messagebox.showerror("Ошибка", f"Не удалось загрузить RF-модель:\n{e}")

def load_another_rf_model():
    """Загрузка другой RF-модели через диалоговое окно"""
    global rf_model
    path = filedialog.askopenfilename(filetypes=[("Pickle files", "*.pkl")])
    if not path:
        return
    try:
        with open(path, 'rb') as f:
            rf_model = pickle.load(f)
        messagebox.showinfo("Успех", f"RF-модель успешно загружена: {path}")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить RF-модель:\n{e}")

def analyze_logs_with_rf():
    """Анализ логов с помощью RF-модели: дописывает столбец 'prediction' и сохраняет в Analyzed Dataset."""
    global rf_model
    if rf_model is None or not hasattr(rf_model, "predict"):
        messagebox.showerror("Ошибка", "Сначала загрузите корректную RF-модель (*.pkl).")
        return

    # Выбор файла логов
    log_path = filedialog.askopenfilename(
        title="Выберите файл логов для RF-анализа",
        filetypes=[("CSV файлы", "*.csv"), ("Все файлы", "*.*")]
    )
    if not log_path:
        return

    try:
        df = pd.read_csv(log_path)

        # Определяем, какие признаки ждёт модель
        if hasattr(rf_model, "feature_names_in_"):
            features = list(rf_model.feature_names_in_)
        else:
            # Если модель старая и не хранит feature_names_in_
            features = [
                'IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS',
                'FLOW_DURATION_MILLISECONDS'
            ]

        missing = [c for c in features if c not in df.columns]
        if missing:
            messagebox.showerror(
                "Ошибка",
                f"В файле отсутствуют столбцы: {', '.join(missing)}"
            )
            return

        X = df[features]
        preds = rf_model.predict(X)

        # Преобразуем предсказания в метки
        df['prediction'] = ['attack' if p else 'benign' for p in preds]

        # Создаём папку для результатов
        output_dir = "Analyzed Dataset"
        os.makedirs(output_dir, exist_ok=True)

        # Формируем имя выходного файла
        base = os.path.splitext(os.path.basename(log_path))[0]
        output_path = os.path.join(output_dir, f"{base}_analyzed.csv")

        # Сохраняем результат
        df.to_csv(output_path, index=False)
        messagebox.showinfo(
            "Успех",
            f"RF-анализ логов завершён, файл сохранён:\n{output_path}"
        )

    except Exception as e:
        messagebox.showerror("Ошибка при RF-анализе логов", str(e))



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

# Определение атак в режиме реального времени
def real_time_analysis():
    import time
    import pandas as pd
    global analysis_running

    if model is None:
        messagebox.showerror("Ошибка", "Сначала загрузите модель.")
        return

    trained_model = model

    while True:
        try:
            # Ждём, пока файл появится
            if not os.path.exists(log_file):
                time.sleep(1)
                continue

            logs_df = pd.read_csv(log_file)

            # Переименование Time → Timestamp
            if 'Time' in logs_df.columns and 'Timestamp' not in logs_df.columns:
                logs_df.rename(columns={'Time': 'Timestamp'}, inplace=True)

            # Проверяем обязательные колонки
            if not {'SRC_ADDR','DST_PORT','Timestamp'}.issubset(logs_df.columns):
                messagebox.showerror(
                    "Ошибка",
                    "Лог должен содержать 'SRC_ADDR', 'DST_PORT' и 'Timestamp'."
                )
                return

            # Парсим время
            logs_df['Timestamp'] = pd.to_datetime(logs_df['Timestamp'], errors='coerce')

            # Получаем тип атаки для каждой записи
            logs_df['Prediction_type'] = trained_model.predict(logs_df)

            # Считываем уже заблокированные IP
            try:
                with open(rules_file, 'r') as f:
                    existing_ips = set(line.split()[0] for line in f if line.strip())
            except FileNotFoundError:
                existing_ips = set()

            # Выбираем IP, для которых модель выдала не 'benign'
            flagged = logs_df.loc[logs_df['Prediction_type'] != 'benign', 'SRC_ADDR']
            to_block = set(flagged) - existing_ips

            if to_block:
                with open(rules_file, 'a') as f:
                    for ip in to_block:
                        # Определяем, какую метку выдала модель именно для этой IP
                        attack_label = (
                            logs_df
                            .loc[(logs_df['SRC_ADDR']==ip) & (logs_df['Prediction_type']!='benign'),
                                 'Prediction_type']
                            .mode()[0]
                        )
                        f.write(f"{ip} deny\n")
                        messagebox.showinfo(
                            "Атака обнаружена",
                            f"IP {ip} заблокирован ({attack_label})"
                        )
                existing_ips |= to_block

            # Обновляем столбец ACTION и сохраняем лог
            logs_df['ACTION'] = logs_df['SRC_ADDR'].apply(
                lambda ip: 'deny' if ip in existing_ips else 'allow'
            )
            logs_df.to_csv(log_file, index=False)

            # Для отладки: выводим распределение типов
            print("→ Распределение по типам атак:\n", logs_df['Prediction_type'].value_counts())

            # Пауза 5 секунд (0.1×50)
            for _ in range(50):
                if not analysis_running:
                    return
                time.sleep(0.1)

        except Exception as e:
            print(f"[ERROR] {e}")
            messagebox.showerror("Ошибка анализа", str(e))
            break




class FakeAttackTypeNet:
    """
    Фейковая многоклассовая модель классификации типа атаки
    по объёму пакетов и сканированию портов.
    """
    def __init__(self):
        self.fitted = True
        # эти метки используются в графике и при построении столбцов
        self.labels = [
            'benign', 'injection', 'ddos', 'scanning', 'dos',
            'password', 'backdoor', 'mitm', 'ransomware', 'xss',
            'unknown attack'
        ]

    def predict(self, X):
        import pandas as pd

        # Проверяем, что пришли нужные колонки
        if not {'SRC_ADDR', 'DST_PORT', 'Timestamp'}.issubset(X.columns):
            raise ValueError("Ожидаются колонки 'SRC_ADDR', 'DST_PORT' и 'Timestamp'")

        df = X.copy()
        # Приводим к datetime и секунда
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Second'] = df['Timestamp'].dt.floor('s')

        # 1) Считаем общее число пакетов от каждой SRC_ADDR за секунду
        counts = (
            df.groupby(['SRC_ADDR','Second'])
              .size()
              .reset_index(name='Count')
        )
        # 2) Считаем число уникальных DST_PORT за секунду (port‐scan)
        port_scans = (
            df.groupby(['SRC_ADDR','Second'])['DST_PORT']
              .nunique()
              .reset_index(name='UniquePorts')
        )

        # Мёрджим обе статистики
        df = df.merge(counts,     on=['SRC_ADDR','Second'], how='left')
        df = df.merge(port_scans, on=['SRC_ADDR','Second'], how='left')

        # Функция-классификатор
        def classify(row):
            c = row['Count']
            p = row.get('UniquePorts', 0) or 0

            # Если за секунду более 50 разных портов → port scan → unknown attack
            if p > 50:
                return 'unknown attack'
            # Иначе по объёму трафика
            if c > 500:
                return 'dos'
            elif c > 100000:
                return 'ddos'
            elif c > 100000:
                return 'scanning'
            elif c > 100000:
                return 'password'
            elif c > 100000:
                return 'mitm'
            elif c >  100000:
                return 'injection'
            elif c >  100000:
                return 'xss'
            elif c >  100000:
                return 'backdoor'
            else:
                return 'benign'

        # Применяем классификацию к каждой строке
        return df.apply(classify, axis=1)


deep_model = None

def deep_load_model():
    global attack_type_model
    try:
        with open('fake_attack_type_model.pkl','rb') as f:
            attack_type_model = pickle.load(f)
        messagebox.showinfo("Успех", "Модель типов атак загружена")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить модель:\n{e}")




def deep_load_another_model():
    """Загрузка другой модели через диалоговое окно"""
    global deep_model
    deep_model_path = filedialog.askopenfilename(filetypes=[("H5 files", "*.h5")])
    
    if deep_model_path:
        try:
            # Загрузка модели в формате h5
           # deep_model = tf.keras.models.load_model(deep_model_path)
            messagebox.showinfo("Успех", f"Модель успешно загружена: {deep_model_path}")
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

        # Создание нового окна для графика
        graph_window = Toplevel()
        graph_window.title("График запросов по IP")
        graph_window.geometry("1400x900")

        # Создание графика
        fig, ax = plt.subplots(figsize=(15, 8), constrained_layout=True)  # Увеличиваем размер графика
        colors = plt.cm.get_cmap("tab10", len(traffic_types))  # 10 цветов

        # Сохраняем текущие пределы осей
        def get_current_limits():
            return ax.get_xlim(), ax.get_ylim()

        def set_limits(xlim, ylim):
            ax.set_xlim(xlim)
            ax.set_ylim(ylim)

        def update_graph():
            """Обновление данных графика."""
            ax.clear()
            width = 0.8 / len(traffic_types)  # Ширина одного столбца
            x_indices = np.arange(len(ip_addresses))  # Индексы для IP-адресов

            for idx, traffic_type in enumerate(traffic_types):
                # Сдвиг столбцов для каждого типа трафика
                x_positions = x_indices + (idx - len(traffic_types) / 2) * width
                bars = ax.bar(
                    x_positions,
                    traffic_data[traffic_type],
                    width=width,
                    label=traffic_type,
                    color=colors(idx),
                    picker=True  # Включаем возможность выбора столбцов
                )

            ax.set_xlabel('IP Address')
            ax.set_ylabel('Количество запросов')
            ax.set_title('Количество запросов по SRC_ADDR для различных типов трафика')

            # Отображение всех меток на оси X
            ax.set_xticks(x_indices)
            ax.set_xticklabels(ip_addresses, rotation=45, ha='right', fontsize=10)

            for spine in ax.spines.values():
                spine.set_linewidth(2)  # Увеличиваем толщину линий графика

            ax.legend(title="Тип трафика", loc='upper left', bbox_to_anchor=(1.05, 1))  # Легенда за пределами графика
            ax.grid(True)

            # Восстанавливаем пределы осей, если они были сохранены
            xlim, ylim = get_current_limits()
            set_limits(xlim, ylim)

            fig.tight_layout()  # Автоматическая подгонка содержимого графика

        def on_click(event: MouseEvent):
            """Вывод информации о столбце при наведении."""
            if event.inaxes == ax:
                for bar in ax.containers:
                    for rect in bar:
                        if rect.contains(event)[0]:
                            ip_idx = int(rect.get_x() + rect.get_width() / 2)
                            if ip_idx < len(ip_addresses):
                                ip = ip_addresses[ip_idx]
                                traffic_type = bar.get_label()
                                count = rect.get_height()
                                messagebox.showinfo(
                                    "Данные столбца",
                                    f"IP: {ip}\nТип трафика: {traffic_type}\nКоличество запросов: {count}"
                                )
                            return

        # Включаем интерактивный режим
        plt.ion()

        # Подключение событий мыши
        fig.canvas.mpl_connect("button_press_event", on_click)

        # Создаем кнопку обновления графика вручную
        update_button = Button(graph_window, text="Обновить график", command=update_graph)
        update_button.pack(side="top", padx=5, pady=5)

        # Вставка графика в окно Tkinter
        canvas = FigureCanvasTkAgg(fig, master=graph_window)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=10, fill='both', expand=True)

        # Вставка панели инструментов matplotlib
        toolbar = NavigationToolbar2Tk(canvas, graph_window)
        toolbar.update()
        toolbar.pack(side="top", fill="x")

        # Первый вызов обновления графика
        update_graph()

    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка при построении графика: {e}")


def attack_type_live_plot():
    import pandas as pd
    from matplotlib.figure import Figure

    global attack_type_model
    if attack_type_model is None:
        messagebox.showerror("Ошибка", "Сначала загрузите модель типов атак.")
        return

    win = Toplevel(root)
    win.title("Типы атак в реальном эфире")

    # Больший холст и tight_layout для меток
    fig = Figure(figsize=(14, 6))
    ax = fig.add_subplot(111)

    # Список типов из модели, с гарантией 'unknown attack'
    types = list(attack_type_model.labels)
    if 'unknown attack' not in types:
        types.append('unknown attack')

    # Кэшируем IP для каждого типа
    ip_type_sets = {}
    ip_by_type = {t: [] for t in types}
    bars = []

    def update(frame):
        nonlocal ip_type_sets, ip_by_type, bars
        ax.clear()
        try:
            df = pd.read_csv(log_file)
            # если колонка 'Time' вместо 'Timestamp'
            if 'Time' in df.columns and 'Timestamp' not in df.columns:
                df.rename(columns={'Time': 'Timestamp'}, inplace=True)
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')

            # предсказание типов
            df['Prediction_type'] = attack_type_model.predict(df)

            # для каждого IP — множество его типов
            ip_type_sets = df.groupby('SRC_ADDR')['Prediction_type'] \
                             .apply(lambda xs: set(xs)).to_dict()
            # обратный словарь: тип → список IP
            ip_by_type = {t: [] for t in types}
            for ip, tset in ip_type_sets.items():
                for t in tset:
                    ip_by_type[t].append(ip)
            # в benign оставляем только тех, кто был исключительно benign
            ip_by_type['benign'] = [
                ip for ip in ip_by_type['benign']
                if ip_type_sets.get(ip, set()) == {'benign'}
            ]

            # считаем пакеты каждого типа
            counts = df['Prediction_type'].value_counts()
            vals = [counts.get(t, 0) for t in types]

            # рисуем столбцы
            bars = ax.bar(types, vals)
            ax.set_ylabel("Количество пакетов")
            ax.set_title("Распределение типов трафика")
            ax.set_xticks(range(len(types)))
            ax.set_xticklabels(types, rotation=45, ha="right", fontsize=8)
            ax.grid(True)
            fig.tight_layout()

        except Exception as e:
            ax.text(0.5, 0.5, f"Ошибка:\n{e}", ha='center', va='center')

    def on_click(event):
        for bar, t in zip(bars, types):
            if bar.contains(event)[0]:
                ips = sorted(ip_by_type.get(t, [])) or ["(нет адресов)"]
                messagebox.showinfo(f"IP-адреса ({t})", "\n".join(ips))
                break

    canvas = FigureCanvasTkAgg(fig, master=win)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    ani = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)
    canvas.mpl_connect("button_press_event", on_click)
    canvas.draw()


def open_ips_window():
    """Открывает новое окно для работы с IPS."""
    global ips_window, real_time_analysis_button
    ips_window = tk.Toplevel()
    ips_window.title("IPS Система")
    ips_window.geometry("600x400")  # Увеличиваем размер окна

    # Фрейм для верхних кнопок
    button_frame_top = tk.Frame(ips_window)
    button_frame_top.pack(pady=10, fill='x')
    # внутри open_ips_window(), в button_frame_top:
    attack_type_rt_button = tk.Button(button_frame_top,
    text="Типы атак в реальном эфире",command=attack_type_live_plot)
    attack_type_rt_button.pack(side="left", padx=5)


    # Верхние кнопки
    #load_deep_model_button = tk.Button(button_frame_top, text="Загрузить глубокую модель", command=deep_load_another_model)
    #load_deep_model_button.pack(side="left", padx=5)

    #deep_analysis_button = tk.Button(button_frame_top, text="Глубокий анализ", command=deep_analyze_logs)
    #deep_analysis_button.pack(side="left", padx=5)

    #analyze_button = tk.Button(button_frame_top, text="Построить график", command=deep_plot_traffic_realtime)
    #analyze_button.pack(side="left", padx=5)

    # Фрейм для нижних кнопок
    button_frame_bottom = tk.Frame(ips_window)
    button_frame_bottom.pack(pady=10, fill='x', side='bottom')

    # Нижние кнопки
    #load_model_button = tk.Button(button_frame_bottom, text="Загрузить модель", command=load_another_model)
    #load_model_button.pack(side="left", padx=5)

    analyze_logs_button = tk.Button(button_frame_bottom, text="Провести анализ", command=analyze_logs_with_rf)
    analyze_logs_button.pack(side="left", padx=5)
    
    # Включить/выключить анализ в реальном времени
    #real_time_analysis_button = tk.Button(button_frame_bottom, text="Включить анализ в реальном времени", command=lambda: threading.Thread(target=real_time_analysis, daemon=True).start())
    #real_time_analysis_button.pack(side="left", padx=5)

# Глобальная переменная для управления потоком анализа
analysis_running = False

# кнопка анализа
def toggle_analysis():
    """Включение/выключение анализа."""
    global analysis_running

    if analysis_button.config('text')[-1] == "Enable Analysis":
        analysis_button.config(text="Disable Analysis", style="Toggled.TButton")
        analysis_running = True
        threading.Thread(target=real_time_analysis, daemon=True).start()
        messagebox.showinfo("Анализ", "Анализ в реальном времени запущен.")
    else:
        analysis_button.config(text="Enable Analysis", style="")
        analysis_running = False
        messagebox.showinfo("Анализ", "Анализ в реальном времени остановлен.")
        
# Кнопка настроек
def open_settings_window():
    window = tk.Tk()
    window.title("Настройки")
    
    # Устанавливаем размеры окна
    window.geometry("300x200")
    
    # Создаем кнопки
    load_defense_button = tk.Button(window, text="Загрузить модель отражения атак", command=load_another_model)
    load_defense_button.pack(side="top", pady=20)

    load_attack_type_button = tk.Button(window, text="Загрузить модель типов атак", command=deep_load_another_model)
    load_attack_type_button.pack(side="bottom", pady=20)

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

style = ttk.Style()
style.configure("Toggled.TButton", background="lightgreen")

analysis_button = ttk.Button(frame_controls, text="Enable Analysis", command=toggle_analysis)
analysis_button.pack(side="left", padx=5)

# Кнопка для открытия окна IPS
ips_button = ttk.Button(frame_controls, text= "IPS ", command=open_ips_window)
ips_button.pack(side="left", padx=5)

# Кнопка для открытия окна IPS
settings_button = ttk.Button(frame_controls, text= "Settings ", command=open_settings_window)
settings_button.pack(side="left", padx=5)

# Фрейм для управления правилами
frame_rules = ttk.Frame(root)
frame_rules.pack(pady=10, fill="x")

ip_entry = ttk.Entry(frame_rules)
ip_entry.pack(side="left", padx=5, fill="x", expand=True)

add_button = ttk.Button(frame_rules, text="Add Rule", command=lambda: add_rule(ip_entry.get()))
add_button.pack(side="left", padx=5)

remove_button = ttk.Button(frame_rules, text="Remove Selected Rule", command=lambda: remove_rule())
remove_button.pack(side="left", padx=5)

clear_button = ttk.Button(frame_rules, text="Clear Rules", command=clear_rules)
clear_button.pack(side="left", padx=5)

# Список текущих правил
rules_listbox = tk.Listbox(root, height=10)
rules_listbox.pack(pady=10, fill="both", expand=True)

# Загрузка правил из файла и запуск отслеживания изменений
load_rules_from_file()
watch_rules_file()

# Обновляем список правил при запуске
update_rules_list()

# Загрузка модели по умолчанию при запуске
load_model()

# Загрузка модели по умолчанию при запуске
deep_load_model()

# Загрузка модели по умолчанию при запуске
load_rf_model()

# Запуск GUI
root.mainloop()

 