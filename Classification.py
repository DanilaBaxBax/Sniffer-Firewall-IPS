#%%
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator, FuncFormatter
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import seaborn as sns

# Загрузка датасета (предполагается, что файл в формате CSV)
#df = pd.read_csv('/Users/danilabaxbax/Desktop/NF-ToN-IoT.csv') #обрезанный
df = pd.read_csv('/Users/danilabaxbax/Desktop/IDS/NF-ToN-IoT.csv') # полный

# Посмотрим на первые несколько строк датасета
print(df.head())

# Подсчитаем количество атак (Label = 1) и не атак (Label = 0)
attack_counts = df['Label'].value_counts()

# Построим график
plt.figure(figsize=(8, 6))
attack_counts.plot(kind='bar', color=['green', 'red'])

# Настроим график
plt.title('Количество атак и нормальных записей в датасете')
plt.xlabel('Label')
plt.ylabel('Количество')
plt.xticks([0, 1], ['Benign', 'Attack'], rotation=0)

# Масштабируем значения на оси Y (умножим на 1 000 000)
plt.gca().set_ylim(0, attack_counts.max() * 1.1)

# Отключаем экспоненциальную нотацию и форматируем числа
plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))
plt.gca().yaxis.set_major_formatter(FuncFormatter(lambda x, _: f'{int(x * 1):,}'))

plt.show()

######################################разбитие на типы атак и классификация######################################
# Подсчитаем количество записей по типам атак (включая Benign)
attack_counts = df['Attack'].value_counts()

# Цвета для графиков (10 цветов)
colors = ['green', 'red', 'blue', 'orange', 'purple', 'cyan', 'magenta', 'yellow', 'brown', 'pink']

# Построим график количества записей для каждого типа атаки
plt.figure(figsize=(10, 6))
attack_counts.plot(kind='bar', color=colors[:len(attack_counts)])
plt.title('Количество записей по типам атак')
plt.xlabel('Тип атаки')
plt.ylabel('Количество')
plt.xticks(rotation=45)
plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))
plt.show()

# Для каждого типа атаки (и Benign) посчитаем средние значения по выбранным столбцам
selected_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']
attack_averages = df.groupby('Attack')[selected_columns].mean()

# Выводим средние значения для каждого типа атаки
print(attack_averages)

# Построим графики для каждого столбца по типам атак
for column in selected_columns:
    plt.figure(figsize=(10, 6))
    attack_averages[column].plot(kind='bar', color=colors[:len(attack_averages)])
    plt.title(f'Среднее значение для {column} по типам атак')
    plt.xlabel('Тип атаки')
    plt.ylabel(f'Среднее значение {column}')
    plt.xticks(rotation=45)
    plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))
    plt.show()

######################################графики для benign и attack, график для их кластеризации######################################

# Отбираем нужные столбцы для анализа
selected_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']

# 1. Средние значения для Benign (Label = 0)
benign_data = df[df['Label'] == 0][selected_columns].mean()

# 2. Средние значения для Attack (Label = 1)
attack_data = df[df['Label'] == 1][selected_columns].mean()

# Вывод средних значений для Benign
print("Средние значения для Benign:")
print(benign_data)

# Вывод средних значений для Attack
print("\nСредние значения для Attack:")
print(attack_data)

# Строим график для Benign
plt.figure(figsize=(10, 6))
sns.barplot(x=benign_data.index, y=benign_data.values, color='green')
plt.title('Средние значения признаков для Benign')
plt.xlabel('Признаки')
plt.ylabel('Средние значения')
plt.xticks(rotation=45)
#plt.yscale('log')  # Применяем логарифмическую шкалу для оси Y
plt.show()

# Строим график для Attack
plt.figure(figsize=(10, 6))
sns.barplot(x=attack_data.index, y=attack_data.values, color='red')
plt.title('Средние значения признаков для Attack')
plt.xlabel('Признаки')
plt.ylabel('Средние значения')
plt.xticks(rotation=45)
#plt.yscale('log')  # Применяем логарифмическую шкалу для оси Y
plt.show()

# 3. Объединяем Benign и Attack для одного графика
combined_data = pd.DataFrame({
    'Label': ['Benign', 'Attack'],
    'IN_BYTES': [benign_data['IN_BYTES'], attack_data['IN_BYTES']],
    'OUT_BYTES': [benign_data['OUT_BYTES'], attack_data['OUT_BYTES']],
    'IN_PKTS': [benign_data['IN_PKTS'], attack_data['IN_PKTS']],
    'OUT_PKTS': [benign_data['OUT_PKTS'], attack_data['OUT_PKTS']],
    'FLOW_DURATION_MILLISECONDS': [benign_data['FLOW_DURATION_MILLISECONDS'], attack_data['FLOW_DURATION_MILLISECONDS']]
})

# Строим график для двух кластеров (Benign и Attack)
combined_data.set_index('Label', inplace=True)
combined_data.plot(kind='bar', figsize=(10, 6))
plt.title('Средние значения признаков для Benign и Attack')
plt.xlabel('Тип данных')
plt.ylabel('Средние значения')
plt.xticks(rotation=0)
plt.yscale('log')  # Применяем логарифмическую шкалу для оси Y
plt.show()
# %%
