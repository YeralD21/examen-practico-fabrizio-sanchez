import pandas as pd
import joblib
import sys

modelo = joblib.load('modelo_anomalias.pkl')
scaler = joblib.load('scaler.pkl')

features = ['dst_port', 'bytes_sent', 'bytes_recv', 'duration_sec',
            'packets', 'ratio_bytes', 'bytes_por_segundo',
            'bytes_total', 'protocol_enc',
            'log_bytes_sent', 'log_duration', 'packets_por_segundo']

archivo = sys.argv[1] if len(sys.argv) > 1 else 'network_traffic.csv'
df = pd.read_csv(archivo)

import numpy as np
df['ratio_bytes'] = df['bytes_sent'] / (df['bytes_recv'] + 1)
df['bytes_por_segundo'] = df['bytes_sent'] / (df['duration_sec'] + 1)
df['bytes_total'] = df['bytes_sent'] + df['bytes_recv']
df['log_bytes_sent'] = np.log1p(df['bytes_sent'])
df['log_duration'] = np.log1p(df['duration_sec'])
df['packets_por_segundo'] = df['packets'] / (df['duration_sec'] + 1)
df['protocol_enc'] = pd.Categorical(df['protocol']).codes

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
