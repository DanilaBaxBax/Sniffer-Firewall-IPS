# build_combined_model.py
import pandas as pd
import pickle

class FakeDoSUnknownNet:
    """
    Объединённая модель: 
      - если за секунду порт-скан (> port_threshold уникальных DST_PORT) → 'unknown attack'
      - elif пакетов/сек > packet_threshold → 'dos'
      - else → 'benign'
    """
    def __init__(self, packet_threshold=500, port_threshold=50):
        self.packet_threshold = packet_threshold
        self.port_threshold   = port_threshold
        self.fitted = True
        self.labels = ['benign', 'dos', 'unknown attack']

    def predict(self, X: pd.DataFrame) -> pd.Series:
        # проверяем колонки
        if not {'Timestamp','SRC_ADDR','DST_PORT'}.issubset(X.columns):
            raise ValueError("Нужны колонки 'Timestamp', 'SRC_ADDR' и 'DST_PORT'")
        df = X.copy()
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df['Second']    = df['Timestamp'].dt.floor('s')

        # считаем кол-во пакетов
        counts = (
            df.groupby(['SRC_ADDR','Second'])
              .size()
              .reset_index(name='Count')
        )
        # считаем число уникальных портов
        scans = (
            df.groupby(['SRC_ADDR','Second'])['DST_PORT']
              .nunique()
              .reset_index(name='UniquePorts')
        )

        # мёрджим обратно
        df = df.merge(counts, on=['SRC_ADDR','Second'], how='left')
        df = df.merge(scans, on=['SRC_ADDR','Second'], how='left')

        def classify(row):
            c = row['Count'] or 0
            p = row['UniquePorts'] or 0
            if p > self.port_threshold:
                return 'unknown attack'
            if c > self.packet_threshold:
                return 'dos'
            return 'benign'

        # применяем и возвращаем серию
        return df.apply(classify, axis=1)

if __name__ == "__main__":
    model = FakeDoSUnknownNet(packet_threshold=500, port_threshold=50)
    with open("fake_dos_unknown_model.pkl", "wb") as f:
        pickle.dump(model, f)
    print("Сохранена модель fake_dos_unknown_model.pkl")
