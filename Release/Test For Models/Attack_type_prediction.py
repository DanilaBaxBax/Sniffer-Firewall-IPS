import pandas as pd
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

# Ожидаемые оригинальные метки
original_labels = ['Benign', 'dos', 'injection', 'ddos', 'scanning', 'password', 'mitm', 'xss', 'backdoor', 'ransomware']

# Загрузка сохранённой модели
model_save_path = '/Users/danilabaxbax/Desktop/traffic_model.h5'
model = tf.keras.models.load_model(model_save_path)
print(f"Model loaded from {model_save_path}")

# Загрузка нового датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/NF-ToN-IoT.csv")

# Создаем LabelEncoder с уже заданными метками
label_encoder = LabelEncoder()
label_encoder.fit(original_labels)  # Используем ваши метки для обучения LabelEncoder

# Разделение данных на признаки (X) для предсказания
X = df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']]

# Стандартизация данных (очень важно для нейронных сетей)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Используем модель для предсказания
y_pred = model.predict(X_scaled)

# Преобразуем вероятности в классы
y_pred_classes = y_pred.argmax(axis=1)  # Получаем предсказанные классы

# Декодируем предсказанные классы обратно в исходные метки
y_pred_labels = label_encoder.inverse_transform(y_pred_classes)

# Добавляем предсказания в DataFrame
df['Prediction'] = y_pred_labels

# Выводим несколько строк с предсказаниями
print(df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS', 'Prediction']].head())

# Сохраняем результат в файл
output_file = '/Users/danilabaxbax/Desktop/Predicted_Network_Traffic.csv'
df.to_csv(output_file, index=False)

print(f"Results with predictions have been saved to {output_file}")
