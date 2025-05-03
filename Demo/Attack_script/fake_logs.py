import pandas as pd
import random
import os

log_path = "C:\\Github\\Sniffer-Firewall-IPS\\Demo\\packet_logs.csv"

# Проверка: загружаем существующий лог, если есть
if os.path.exists(log_path):
    existing_df = pd.read_csv(log_path)
    print(f"[+] Загружено {len(existing_df)} существующих записей.")
else:
    print("[!] Файл не найден, будет создан новый.")
    existing_df = pd.DataFrame(columns=[
        'SRC_ADDR', 'DST_ADDR', 'IN_BYTES', 'OUT_BYTES',
        'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS',
        'SRC_PORT', 'DST_PORT', 'ACTION'
    ])

# Генерация DDoS-записей
ddos_entries = 1000
ddos_data = {
    'SRC_ADDR': ['192.168.1.100'] * ddos_entries,
    'DST_ADDR': ['10.0.0.1'] * ddos_entries,
    'IN_BYTES': [random.randint(100, 10000) for _ in range(ddos_entries)],
    'OUT_BYTES': [random.randint(100, 10000) for _ in range(ddos_entries)],
    'IN_PKTS': [random.randint(1, 100) for _ in range(ddos_entries)],
    'OUT_PKTS': [random.randint(1, 100) for _ in range(ddos_entries)],
    'FLOW_DURATION_MILLISECONDS': [random.randint(1, 1000) for _ in range(ddos_entries)],
    'SRC_PORT': [random.randint(1024, 65535) for _ in range(ddos_entries)],
    'DST_PORT': [80] * ddos_entries,
    'ACTION': ['Deny'] * ddos_entries,
}

df_ddos = pd.DataFrame(ddos_data)

# Убедимся, что у старых данных есть колонка ACTION
if 'ACTION' not in existing_df.columns:
    existing_df['ACTION'] = 'allow'

# Объединение и перемешивание
combined_df = pd.concat([existing_df, df_ddos], ignore_index=True)
combined_df = combined_df.sample(frac=1).reset_index(drop=True)

# Сохраняем обратно
combined_df.to_csv(log_path, index=False)

print(f"[✔] Добавлено {ddos_entries} DDoS-записей с ACTION='deny'. Всего: {len(combined_df)} строк.")
