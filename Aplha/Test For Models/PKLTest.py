import pandas as pd
import pickle

# Путь к файлу с обученной моделью
model_file_path = "/Users/danilabaxbax/Desktop/random_forest_model.pkl"

# Загрузка обученной модели из pkl-файла
with open(model_file_path, 'rb') as file:
    trained_model = pickle.load(file)

# Проверяем, что загруженный объект поддерживает метод predict
if not hasattr(trained_model, "predict"):
    raise ValueError("Загруженный объект не является моделью машинного обучения. Проверьте содержимое файла!")

# Загрузка датасета из CSV для анализа
dataset_file_path = "/Users/danilabaxbax/Desktop/IDS/packet_logs.csv"
df = pd.read_csv(dataset_file_path)

# Проверка наличия необходимых столбцов
required_columns = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']
if not all(column in df.columns for column in required_columns):
    raise ValueError("Некоторые из требуемых столбцов отсутствуют в датасете!")

# Применение модели для предсказания
features = df[required_columns]  # Выбор нужных столбцов
df['Prediction'] = trained_model.predict(features)  # Предсказания модели

# Сохранение проанализированного датасета в файлы
#output_pkl_path = "/Users/danilabaxbax/Desktop/IDS/Analyzed_Dataset.pkl"
output_csv_path = "/Users/danilabaxbax/Desktop/IDS/Analyzed_Dataset.csv"

#df.to_pickle(output_pkl_path)  # Сохраняем в PKL
df.to_csv(output_csv_path, index=False)  # Сохраняем в CSV

# Сообщение о завершении
print("Анализ завершён! Проанализированный датасет сохранён:")
#print(f"- PKL: {output_pkl_path}")
print(f"- CSV: {output_csv_path}")
