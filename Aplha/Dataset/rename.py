import pandas as pd

# Загрузка CSV файла
df = pd.read_csv('/Users/danilabaxbax/Desktop/Release/Dataset/NF-ToN-IoT.csv')

# Переименование столбцов
df.columns = [col.replace('L4_', '').replace('IPV4_', '') for col in df.columns]

# Сохранение результата в новый файл
df.to_csv('/Users/danilabaxbax/Desktop/Release/Dataset/NF-ToN-IoT-renamed.csv', index=False)

print("Столбцы переименованы и файл сохранен как NF-ToN-IoT-renamed.csv")
