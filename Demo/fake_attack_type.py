import pandas as pd
import pickle

class FakeAttackTypeNet:
    """
    Фейковая многоклассовая модель классификации типа атаки
    по количеству пакетов в секунду.
    """
    def __init__(self):
        self.fitted = True
        # Метки для типов трафика
        self.labels = [
            'benign', 'injection', 'ddos', 'scanning', 'dos',
            'password', 'backdoor', 'mitm', 'ransomware', 'xss'
        ]

    def predict(self, X: pd.DataFrame) -> pd.Series:
        """
        Ожидает DataFrame с колонками 'SRC_ADDR' и 'Timestamp'.
        Возвращает pd.Series с предсказанным типом трафика.
        """
        if 'SRC_ADDR' not in X.columns or 'Timestamp' not in X.columns:
            raise ValueError("Ожидаются колонки 'SRC_ADDR' и 'Timestamp'")
        df = X.copy()
        df['Second'] = pd.to_datetime(df['Timestamp'], errors='coerce').dt.floor('s')
        # Подсчёт пакетов за секунду
        counts = df.groupby(['SRC_ADDR', 'Second']).size().reset_index(name='Count')
        df = df.merge(counts, on=['SRC_ADDR', 'Second'], how='left')
        # Классификация по порогам
        def classify(c):
            if c>500: return 'ddos'
            elif c>100000: return 'scanning'
            elif c>100000: return 'dos'
            elif c>100000: return 'password'
            elif c>100000: return 'mitm'
            elif c>100000: return 'injection'
            elif c>100000: return 'xss'
            elif c>100000:  return 'backdoor'
            elif c>100000:  return 'ransomware'
            else:      return 'benign'
        return df['Count'].apply(classify)

# Создание экземпляра и сохранение в pickle
if __name__ == "__main__":
    model = FakeAttackTypeNet()
    with open("fake_attack_type_model.pkl", "wb") as f:
        pickle.dump(model, f)
    print("Модель FakeAttackTypeNet успешно сохранена в fake_attack_type_model.pkl")
