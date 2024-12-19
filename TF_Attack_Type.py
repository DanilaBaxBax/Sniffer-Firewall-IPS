import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt

# Загрузка датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/IDS/NF-ToN-IoT.csv")

# Преобразуем типы трафика из столбца 'Attack' в числовые значения с помощью LabelEncoder
label_encoder = LabelEncoder()
df['Attack'] = label_encoder.fit_transform(df['Attack'])  # Преобразуем метки в числа

# Разделение данных на признаки (X) и метки (y)
X = df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']]
y = df['Attack']  # Метки теперь в поле 'Attack'

# Сохраняем индексы исходного датасета
df['Original_Index'] = df.index  # Добавляем столбец с исходными индексами

# Разделение на обучающую и тестовую выборки
X_train, X_test, y_train, y_test, train_indices, test_indices = train_test_split(
    X, y, df['Original_Index'], test_size=0.2, random_state=42
)

# Стандартизация данных (очень важно для нейронных сетей)
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Создание модели нейронной сети
model = tf.keras.Sequential()

# Добавление слоев нейронной сети
model.add(tf.keras.layers.Dense(64, input_dim=X_train.shape[1], activation='relu'))  # Входной слой
model.add(tf.keras.layers.Dense(128, activation='relu'))  # Промежуточный слой
model.add(tf.keras.layers.Dense(64, activation='relu'))  # Промежуточный слой
model.add(tf.keras.layers.Dense(10, activation='softmax'))  # Выходной слой с 10 классами (типами трафика)

# Компиляция модели
model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])

# Обучение модели с сохранением истории обучения
history = model.fit(X_train, y_train, epochs=20, batch_size=32, validation_data=(X_test, y_test))

# Оценка модели
y_pred = model.predict(X_test)
y_pred_classes = y_pred.argmax(axis=1)  # Получаем предсказанные классы

# Оценка точности
accuracy = accuracy_score(y_test, y_pred_classes)
print(f"Accuracy of the model on test data: {accuracy * 100:.2f}%")

# Точность на обучающих данных (train data)
train_accuracy = history.history['accuracy'][-1]  # Последняя эпоха
print(f"Accuracy of the model on training data: {train_accuracy * 100:.2f}%")

# Декодируем предсказанные классы обратно в исходные метки
y_pred_labels = label_encoder.inverse_transform(y_pred_classes)
y_test_labels = label_encoder.inverse_transform(y_test)

# Создаем DataFrame с данными, предсказанным типом трафика и реальным типом трафика
output_df = pd.DataFrame({
    'Original_Index': test_indices,  # Добавляем индекс для восстановления порядка
    'IN_BYTES': X_test[:, 0], 
    'OUT_BYTES': X_test[:, 1], 
    'IN_PKTS': X_test[:, 2], 
    'OUT_PKTS': X_test[:, 3], 
    'FLOW_DURATION_MILLISECONDS': X_test[:, 4], 
    'Predicted_Traffic_Type': y_pred_labels, 
    'Actual_Traffic_Type': y_test_labels
})

# Сортируем DataFrame по исходному индексу, чтобы строки шли в том же порядке, что и в исходном датасете
output_df = output_df.sort_values(by='Original_Index')

# Выводим несколько строк
print(output_df.head())

# Сохраняем результат в файл
output_file = '/Users/danilabaxbax/Desktop/Output_NN_Traffic_Types.txt'
output_df.to_csv(output_file, index=False)

print(f"Results have been saved to {output_file}")

# Построение графиков точности на тренировочной и тестовой выборке
train_acc = history.history['accuracy']
val_acc = history.history['val_accuracy']

plt.plot(train_acc, label='Training Accuracy')
plt.plot(val_acc, label='Test Accuracy')
plt.xlabel('Epochs')
plt.ylabel('Accuracy')
plt.legend()
plt.title('Training and Test Accuracy')
plt.show()
