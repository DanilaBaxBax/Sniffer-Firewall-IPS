import pandas as pd
import tensorflow as tf
from sklearn.preprocessing import StandardScaler

# Ожидаемые метки: "Benign" и "Attack"
original_labels = ['Benign', 'Attack']

# Загрузка сохранённой модели
model_save_path = '/Users/danilabaxbax/Desktop/traffic_model.h5'
model = tf.keras.models.load_model(model_save_path)
print(f"Model loaded from {model_save_path}")

# Загрузка нового датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/Release/Dataset/NF-ToN-IoT.csv")

# Преобразуем типы трафика из столбца 'Attack' в бинарные метки (Benign = 0, Attack = 1)
df['Attack'] = df['Attack'].apply(lambda x: 1 if x != 'Benign' else 0)

# Разделение данных на признаки (X) для предсказания
X = df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']]

# Стандартизация данных
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Проверка размера входных данных
print(f"Shape of input data: {X_scaled.shape}")
print(f"Shape of the dataframe: {df.shape}")

# Используем модель для предсказания
y_pred = model.predict(X_scaled)

# Проверка, что предсказания имеют ту же размерность, что и входные данные
print(f"Shape of predictions: {y_pred.shape}")

# Печать вероятностей для диагностики
print("Predicted probabilities:")
print(y_pred)

# Определение меток на основе вероятности для класса "Attack"
# Предполагаем, что первый столбец — это вероятность для класса "Benign", а второй для "Attack"
y_pred_classes = (y_pred[:, 1] > 0.5).astype("int32")  # Используем второй столбец для вероятности "Attack"

# Декодируем предсказанные классы обратно в исходные метки
y_pred_labels = ['Benign' if label == 0 else 'Attack' for label in y_pred_classes.flatten()]

# Убедимся, что размерность предсказаний совпадает с количеством строк в df
print(f"Length of predictions: {len(y_pred_labels)}")
print(f"Length of df: {len(df)}")

# Добавляем предсказания в DataFrame
df['Prediction'] = y_pred_labels

# Выводим несколько строк с предсказаниями
print(df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS', 'Prediction']].head())

# Сохраняем результат в файл
output_file = '/Users/danilabaxbax/Desktop/Predicted_Network_Traffic.csv'
df.to_csv(output_file, index=False)

print(f"Results with predictions have been saved to {output_file}")
