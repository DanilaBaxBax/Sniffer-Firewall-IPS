import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.tree import plot_tree

# Загрузка датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/IDS/NF-ToN-IoT.csv")

# Разделение данных на признаки и метки
X = df[['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']]
y = df['Label']  # метка 0 - Benign, 1 - Attack

# Разделение на обучающую и тестовую выборки
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Инициализация и обучение модели RandomForest
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
rf_classifier.fit(X_train, y_train)

# Прогнозирование на тестовой выборке
y_pred_test = rf_classifier.predict(X_test)

# Оценка точности на тестовой выборке
accuracy_test = accuracy_score(y_test, y_pred_test)

# Прогнозирование на обучающей выборке
y_pred_train = rf_classifier.predict(X_train)

# Оценка точности на обучающей выборке
accuracy_train = accuracy_score(y_train, y_pred_train)

# Создание новых колонок в оригинальном датафрейме
df['Prediction'] = rf_classifier.predict(X)  # Прогнозируем для всего датасета
df['Benign_or_Attack'] = df['Label'].apply(lambda x: 'Benign' if x == 0 else 'Attack')

# Формирование текста для записи в файл
output_text = f"Accuracy of the model on test set: {accuracy_test * 100:.2f}%\n"
output_text += f"Accuracy of the model on train set: {accuracy_train * 100:.2f}%\n\n"
output_text += "Predictions and Actual Labels:\n"
output_text += pd.DataFrame({'IN_BYTES': df['IN_BYTES'], 'OUT_BYTES': df['OUT_BYTES'], 'IN_PKTS': df['IN_PKTS'],
                             'OUT_PKTS': df['OUT_PKTS'], 'FLOW_DURATION_MILLISECONDS': df['FLOW_DURATION_MILLISECONDS'],
                             'Prediction': df['Prediction'], 'Benign_or_Attack': df['Benign_or_Attack']}).to_string(index=False)

# Выводим в консоль то, что будет записано в файл
#print(output_text)

# Запись в файл
output_file = '/Users/danilabaxbax/Desktop/Output_RF.txt'
with open(output_file, 'w') as f:
    f.write(output_text)

# Выводим точности для теста и тренировки в консоль
print(f"Accuracy of the model on test set: {accuracy_test * 100:.2f}%")
print(f"Accuracy of the model on train set: {accuracy_train * 100:.2f}%")

# График важности признаков RandomForest
feature_importances = rf_classifier.feature_importances_
features = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS']

plt.figure(figsize=(10, 6))
sns.barplot(x=features, y=feature_importances)
plt.title('Feature Importance for RandomForest Classifier')
plt.ylabel('Importance')
plt.xlabel('Features')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Визуализация одного дерева классификации из RandomForest
# Для этого выбираем первое дерево из ансамбля
plt.figure(figsize=(15, 10))
plot_tree(rf_classifier.estimators_[0], feature_names=features, filled=True, rounded=True, class_names=['Benign', 'Attack'])
plt.title("Visualization of a Single Decision Tree from RandomForest")
plt.show()
