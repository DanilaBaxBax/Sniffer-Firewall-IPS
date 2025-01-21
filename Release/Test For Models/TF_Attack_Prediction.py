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
df = pd.read_csv("/Users/danilabaxbax/Downloads/packet_logs-3.csv")

# Проверяем, какие столбцы доступны в новом датасете
print(f"Columns in the dataset: {df.columns}")

# Указываем столбцы с признаками для предсказаний
feature_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 
                   'FLOW_DURATION_MILLISECONDS', 'SRC_PORT', 'DST_PORT']

# Убедимся, что все необходимые столбцы есть в датасете
for col in feature_columns:
    if col not in df.columns:
        raise KeyError(f"Column {col} is missing in the dataset.")

# Разделение данных на признаки (X)
X = df[feature_columns]

# Стандартизация данных
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Используем модель для предсказания
y_pred = model.predict(X_scaled)

# Определение меток на основе вероятности для класса "Attack"
y_pred_classes = (y_pred[:, 1] > 0.5).astype("int32")

# Декодируем предсказанные классы обратно в метки
y_pred_labels = ['Benign' if label == 0 else 'Attack' for label in y_pred_classes.flatten()]

# Добавляем предсказания в DataFrame
df['Prediction'] = y_pred_labels

# Выводим несколько строк с предсказаниями
print(df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 
          'FLOW_DURATION_MILLISECONDS', 'Prediction']].head())

# Сохраняем результат в файл
output_file = '/Users/danilabaxbax/Desktop/Predicted_Network_Traffic.csv'
df.to_csv(output_file, index=False)

print(f"Results with predictions have been saved to {output_file}")
