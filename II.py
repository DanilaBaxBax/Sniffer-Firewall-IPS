import pandas as pd

# Функция для классификации на основе закономерностей
def classify_traffic(features):
    # Средние значения для Benign
    benign_mean = {
        'IN_BYTES': 5437.066465,
        'OUT_BYTES': 3982.786247,
        'IN_PKTS': 69.420784,
        'OUT_PKTS': 34.084979,
        'FLOW_DURATION_MILLISECONDS': 28641.741438
    }
    
    # Средние значения для Attack
    attack_mean = {
        'IN_BYTES': 498.475501,
        'OUT_BYTES': 2443.872586,
        'IN_PKTS': 5.478282,
        'OUT_PKTS': 5.015118,
        'FLOW_DURATION_MILLISECONDS': 1270.000934
    }

    # Допустимые отклонения для классификации как Benign
    benign_deviation = {
        'IN_BYTES': 2000,
        'OUT_BYTES': 1000,
        'IN_PKTS': 10,
        'OUT_PKTS': 5,
        'FLOW_DURATION_MILLISECONDS': 10000
    }

    # Классификация на основе разницы с порогами и отклонений
    attack_score = 0
    benign_score = 0

    for key in features.keys():
        if features[key] == 0:
            if benign_mean[key] > 1000:
                benign_score += 100
            else:
                benign_score += 0
        elif abs(features[key] - benign_mean[key]) <= benign_deviation[key]:
            benign_score += 100
        elif features[key] < attack_mean[key]:
            attack_score += 100
        else:
            benign_score += 50

    if attack_score > benign_score:
        return "Attack"
    else:
        return "Benign"


# Загрузка датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/IDS/NF-ToN-IoT.csv")

# Печать всех названий столбцов
print("Columns in dataset:", df.columns)

# Для каждой строки в датасете делаем классификацию
predictions = []
for index, row in df.iterrows():
    features = {
        'IN_BYTES': row['IN_BYTES'],
        'OUT_BYTES': row['OUT_BYTES'],
        'IN_PKTS': row['IN_PKTS'],
        'OUT_PKTS': row['OUT_PKTS'],
        'FLOW_DURATION_MILLISECONDS': row['FLOW_DURATION_MILLISECONDS']
    }
    prediction = classify_traffic(features)
    predictions.append(prediction)

# Добавление предсказаний в датасет
df['Prediction'] = predictions

# Заполнение столбца 'Attack_or_Benign' на основе значений из столбца 'Label':
df['Attack_or_Benign'] = df['Label'].apply(lambda x: 'Benign' if x == 0 else 'Attack')

# Подсчет точности работы модели
correct_predictions = sum(df['Prediction'] == df['Attack_or_Benign'])
total_predictions = len(df)
accuracy = correct_predictions / total_predictions

# Выводим точность
print(f"Accuracy of the model: {accuracy * 100:.2f}%")

# Выводим результат
print(df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS', 'Prediction', 'Attack_or_Benign']])
