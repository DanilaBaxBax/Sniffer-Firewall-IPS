# build_attack_type_model.py
import pandas as pd
import pickle

class FakeAttackTypeNet:
    """
    Фейковая многоклассовая модель классификации типа атаки
    по количеству пакетов и по сканированию портов.
    """
    def __init__(self):
        self.fitted = True
        self.labels = [
            'benign', 'injection', 'ddos', 'scanning', 'dos',
            'password', 'backdoor', 'mitm', 'ransomware', 'xss',
            'unknown attack'
        ]

    def predict(self, X: pd.DataFrame) -> pd.Series:
        if not {'SRC_ADDR','DST_PORT','Timestamp'}.issubset(X.columns):
            raise ValueError("Ожидаются колонки 'SRC_ADDR','DST_PORT' и 'Timestamp'")
        df = X.copy()
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Second'] = df['Timestamp'].dt.floor('s')

        # 1) Считаем общее количество пакетов
        counts = df.groupby(['SRC_ADDR','Second']).size().reset_index(name='Count')
        # 2) Считаем число уникальных портов за секунду
        port_scans = (
            df.groupby(['SRC_ADDR','Second'])['DST_PORT']
              .nunique()
              .reset_index(name='UniquePorts')
        )

        # Сливаем
        df = df.merge(counts,     on=['SRC_ADDR','Second'], how='left')
        df = df.merge(port_scans, on=['SRC_ADDR','Second'], how='left')

        def classify(row):
            c = row['Count']
            p = row['UniquePorts'] or 0

            # Если видим сканирование портов >50 портов/сек – неизвестная атака
            if p > 50:
                return 'unknown attack'
            # далее – старые пороги по объёму
            if c > 500:
                return 'ddos'
            elif c > 300:
                return 'dos'
            elif c > 200:
                return 'scanning'
            elif c > 150:
                return 'password'
            elif c > 100:
                return 'mitm'
            elif c >  75:
                return 'injection'
            elif c >  50:
                return 'xss'
            elif c >  20:
                return 'backdoor'
            else:
                return 'benign'

        # Применяем классификацию по каждой строке
        return df.apply(classify, axis=1)

if __name__ == "__main__":
    model = FakeAttackTypeNet()
    with open("fake_attack_type_model.pkl", "wb") as f:
        pickle.dump(model, f)
    print("Модель FakeAttackTypeNet пересохранена с детекцией port scan → unknown attack")
