import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import pickle

# Загрузка датасета
df = pd.read_csv("/Users/danilabaxbax/Desktop/Release/Dataset/NF-ToN-IoT-renamed.csv")

# Кодирование SRC и DST IP
label_encoder_src = LabelEncoder()
label_encoder_dst = LabelEncoder()
df['SRC_ADDR_Encoded'] = label_encoder_src.fit_transform(df['SRC_ADDR'])
df['DST_ADDR_Encoded'] = label_encoder_dst.fit_transform(df['DST_ADDR'])

# Признаки и целевая переменная
features = ['IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS',
            'SRC_PORT', 'DST_PORT']
X = df[features]
y = df['Label']  # 0 - Benign, 1 - Attack

# Разделение выборки
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# RandomForest с балансировкой классов
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
rf_classifier.fit(X_train, y_train)

# Прогноз
y_pred_train = rf_classifier.predict(X_train)
y_pred_test = rf_classifier.predict(X_test)

# Оценка
accuracy_train = accuracy_score(y_train, y_pred_train)
accuracy_test = accuracy_score(y_test, y_pred_test)

# Отчёты
print("\n[Classification Report]")
print(classification_report(y_test, y_pred_test, target_names=['Benign', 'Attack']))

print("\n[Confusion Matrix]")
print(confusion_matrix(y_test, y_pred_test))

# Кросс-валидация
cv_scores = cross_val_score(rf_classifier, X, y, cv=5)
print(f"\n[Cross-validation accuracy]: {cv_scores.mean():.2f}")

# Сохраняем ошибки классификации
df_errors = X_test.copy()
df_errors['True_Label'] = y_test
df_errors['Predicted_Label'] = y_pred_test
df_errors = df_errors[df_errors['True_Label'] != df_errors['Predicted_Label']]

df_errors.to_csv('/Users/danilabaxbax/Desktop/prediction_errors.csv', index=False)
print("\n[Errors saved to prediction_errors.csv]")

# Важность признаков
plt.figure(figsize=(10, 6))
sns.barplot(x=features, y=rf_classifier.feature_importances_)
plt.title('Feature Importance')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Сохраняем модель
model_data = {
    "model": rf_classifier,
    "label_encoder_src": label_encoder_src,
    "label_encoder_dst": label_encoder_dst
}
pkl_file_path = '/Users/danilabaxbax/Desktop/random_forest_model-balanced.pkl'
with open(pkl_file_path, 'wb') as file:
    pickle.dump(model_data, file)

print(f"\n[Model saved to: {pkl_file_path}]")
print(f"[Train Accuracy]: {accuracy_train:.2f}")
print(f"[Test Accuracy]: {accuracy_test:.2f}")
