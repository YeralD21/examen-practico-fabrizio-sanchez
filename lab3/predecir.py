import pandas as pd
import numpy as np
import joblib
import sys

modelo = joblib.load('modelo_anomalias.pkl')
scaler = joblib.load('scaler.pkl')

features = ['bytes_sent_log', 'bytes_recv_log', 'duration_sec',
            'packets', 'dst_port', 'ratio_bytes_log', 'bytes_por_segundo_log']

archivo = sys.argv[1] if len(sys.argv) > 1 else 'network_traffic.csv'
df = pd.read_csv(archivo)

df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_por_segundo'] = (df['bytes_sent'] + df['bytes_recv']) / (df['duration_sec'] + 1)
for col in ['bytes_sent', 'bytes_recv', 'ratio_bytes', 'bytes_por_segundo']:
    df[col + '_log'] = np.log1p(df[col])

X = scaler.transform(df[features])
scores = modelo.decision_function(X)
predicciones = modelo.predict(X)

df['anomaly_score'] = scores
df['prediccion'] = ['ANOMALIA' if p == -1 else 'normal' for p in predicciones]

anomalias = df[df['prediccion'] == 'ANOMALIA']
print(f"Total registros analizados: {len(df)}")
print(f"Anomalias detectadas: {len(anomalias)}")
print(f"\nTop 5 anomalias mas criticas:")
print(anomalias.nsmallest(5, 'anomaly_score')[
    ['src_ip','dst_ip','dst_port','protocol','bytes_sent','anomaly_score','prediccion']
].to_string())
