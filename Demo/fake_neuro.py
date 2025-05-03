import pandas as pd
import pickle

class FakeNeuralNet:
    def __init__(self, threshold=500):
        self.threshold = threshold
        self.fitted = True
        self.addr_counts = None  # не используется, но оставим на будущее

    def predict(self, X):
        if not isinstance(X, pd.DataFrame):
            raise ValueError("Ожидается pandas DataFrame")

        if 'SRC_ADDR' not in X.columns or 'Timestamp' not in X.columns:
            raise ValueError("Необходимые столбцы: 'SRC_ADDR' и 'Timestamp'")

        df = X.copy()
        df['Second'] = pd.to_datetime(df['Timestamp'], errors='coerce').dt.floor('s')

        grouped = df.groupby(['SRC_ADDR', 'Second']).size().reset_index(name='Count')
        df = df.merge(grouped, on=['SRC_ADDR', 'Second'], how='left')

        return (df['Count'] > self.threshold).astype(int)

# Создание и сохранение модели
model = FakeNeuralNet(threshold=850)

with open("fake_neural_net.pkl", "wb") as f:
    pickle.dump(model, f)

print("Модель FakeNeuralNet успешно сохранена в fake_neural_net.pkl")
