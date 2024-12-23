import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler

# Загрузка датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/IDS/NF-ToN-IoT.csv")

# Извлекаем уникальные метки до преобразования
original_labels = df['Attack'].unique()
print(f"Original labels: {original_labels}")

# Сохраняем уникальные метки в файл
labels_file_path = '/Users/danilabaxbax/Desktop/original_labels2.txt'
with open(labels_file_path, 'w') as f:
    for label in original_labels:
        f.write(f"{label}\n")

print(f"Original labels have been saved to {labels_file_path}")

# Преобразуем типы трафика из столбца 'Attack' в бинарные метки (Benign = 0, Attack = 1)
df['Attack'] = df['Attack'].apply(lambda x: 1 if x != 'Benign' else 0)

# Разделение данных на признаки (X) и метки (y)
X = df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']]
y = df['Attack']  # Метки теперь бинарные (0 - Benign, 1 - Attack)

# Сохраняем индексы исходного датасета
df['Original_Index'] = df.index  # Добавляем столбец с исходными индексами

# Разделение на обучающую и тестовую выборки
X_train, X_test, y_train, y_test, train_indices, test_indices = train_test_split(
    X, y, df['Original_Index'], test_size=0.2, random_state=42
)

# Стандартизация данных
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Создание модели нейронной сети
model = tf.keras.Sequential()

# Добавление слоев нейронной сети
model.add(tf.keras.layers.Dense(64, input_dim=X_train.shape[1], activation='relu'))  # Входной слой
model.add(tf.keras.layers.Dense(128, activation='relu'))  # Промежуточный слой
model.add(tf.keras.layers.Dense(64, activation='relu'))  # Промежуточный слой
model.add(tf.keras.layers.Dense(1, activation='sigmoid'))  # Выходной слой (1 нейрон для бинарной классификации)

# Компиляция модели
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Обучение модели с сохранением истории обучения
history = model.fit(X_train, y_train, epochs=12, batch_size=32, validation_data=(X_test, y_test))

# Оценка модели
y_pred = model.predict(X_test)
y_pred_classes = (y_pred > 0.5).astype("int32")  # Преобразуем вероятности в классы (0 или 1)

# Оценка точности
accuracy = accuracy_score(y_test, y_pred_classes)  # Оценка точности
print(f"Accuracy of the model on test data: {accuracy * 100:.2f}%")

# Точность на обучающих данных (train data)
train_accuracy = history.history['accuracy'][-1]  # Последняя эпоха
print(f"Accuracy of the model on training data: {train_accuracy * 100:.2f}%")

# Создаем DataFrame с данными, предсказанным типом трафика и реальным типом трафика
output_df = pd.DataFrame({
    'Original_Index': test_indices,  # Добавляем индекс для восстановления порядка
    'IN_BYTES': X_test[:, 0], 
    'OUT_BYTES': X_test[:, 1], 
    'IN_PKTS': X_test[:, 2], 
    'OUT_PKTS': X_test[:, 3], 
    'FLOW_DURATION_MILLISECONDS': X_test[:, 4], 
    'Predicted_Traffic_Type': ['Benign' if label == 0 else 'Attack' for label in y_pred_classes.flatten()],
    'Actual_Traffic_Type': ['Benign' if label == 0 else 'Attack' for label in y_test]
})

# Сортируем DataFrame по исходному индексу, чтобы строки шли в том же порядке, что и в исходном датасете
output_df = output_df.sort_values(by='Original_Index')

# Выводим несколько строк
print(output_df.head())

# Сохраняем результат в файл
output_file = '/Users/danilabaxbax/Desktop/Attack_Model.txt'
output_df.to_csv(output_file, index=False)

print(f"Results have been saved to {output_file}")

# Сохраняем модель
model_save_path = '/Users/danilabaxbax/Desktop/Attack_Model.h5'
model.save(model_save_path)
print(f"Model has been saved to {model_save_path}")

# Построение графиков точности на тренировочной и тестовой выборке
train_acc = history.history['accuracy']
val_acc = history.history['val_accuracy']

plt.plot(train_acc, label='Training Accuracy')
plt.plot(val_acc, label='Validation Accuracy')
plt.title('Training and Validation Accuracy')
plt.xlabel('Epochs')
plt.ylabel('Accuracy')
plt.legend()
plt.show()
