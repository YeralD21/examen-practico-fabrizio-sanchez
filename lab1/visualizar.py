import re
import json
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
from datetime import datetime
import numpy as np

os.makedirs("graficas", exist_ok=True)

# ── Cargar datos SSH ──────────────────────────────────────
conteo_ssh = defaultdict(int)
with open("auth.log", "r") as f:
    for linea in f:
        if "Failed password" in linea:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", linea)
            if match:
                conteo_ssh[match.group(1)] += 1

top10_ssh = sorted(conteo_ssh.items(), key=lambda x: x[1], reverse=True)[:10]

# ── Cargar datos HTTP ─────────────────────────────────────
horas = defaultdict(int)
calor = defaultdict(lambda: defaultdict(int))

with open("access.log", "r") as f:
    for linea in f:
        match = re.match(r'\S+ \S+ \S+ \[(.+?)\] "\S+ \S+ \S+" (\d+)', linea)
        if not match:
            continue
        try:
            fecha = datetime.strptime(match.group(1)[:20], "%d/%b/%Y:%H:%M:%S")
            codigo = match.group(2)
            horas[fecha.hour] += 1
            calor[fecha.hour][codigo] += 1
        except:
            continue

# ── GRAFICA 1: Top 10 IPs SSH ─────────────────────────────
ips = [x[0] for x in top10_ssh]
intentos = [x[1] for x in top10_ssh]

fig, ax = plt.subplots(figsize=(12, 6))
bars = ax.barh(ips[::-1], intentos[::-1], color=['#d32f2f' if i >= 50 else '#f57c00' if i >= 20 else '#388e3c' for i in intentos[::-1]])
ax.set_xlabel("Intentos fallidos SSH")
ax.set_title("Top 10 IPs con más intentos fallidos SSH\n(Rojo = supera umbral 50, Naranja = sospechoso, Verde = bajo)", fontsize=12)
ax.axvline(x=50, color='red', linestyle='--', alpha=0.7, label='Umbral alerta (50)')
ax.legend()
plt.tight_layout()
plt.savefig("graficas/top10_ssh.png", dpi=150)
plt.close()
print("✓ top10_ssh.png generada")

# ── GRAFICA 2: Timeline HTTP por hora ────────────────────
horas_lista = list(range(24))
conteos_hora = [horas.get(h, 0) for h in horas_lista]

fig, ax = plt.subplots(figsize=(12, 5))
ax.plot(horas_lista, conteos_hora, marker='o', color='#1976D2', linewidth=2)
ax.fill_between(horas_lista, conteos_hora, alpha=0.2, color='#1976D2')
ax.set_xlabel("Hora del día")
ax.set_ylabel("Número de peticiones HTTP")
ax.set_title("Distribución de peticiones HTTP por hora del día")
ax.set_xticks(horas_lista)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig("graficas/timeline_http.png", dpi=150)
plt.close()
print("✓ timeline_http.png generada")

# ── GRAFICA 3: Heatmap hora vs código HTTP ───────────────
codigos_principales = ['200', '301', '302', '400', '403', '404', '500']
matriz = []
for h in range(24):
    fila = [calor[h].get(c, 0) for c in codigos_principales]
    matriz.append(fila)

matriz_np = np.array(matriz)
fig, ax = plt.subplots(figsize=(12, 8))
sns.heatmap(matriz_np, xticklabels=codigos_principales,
            yticklabels=[f"{h:02d}:00" for h in range(24)],
            cmap='YlOrRd', ax=ax, linewidths=0.5)
ax.set_title("Mapa de calor: Peticiones por hora vs Código de respuesta HTTP")
ax.set_xlabel("Código HTTP")
ax.set_ylabel("Hora del día")
plt.tight_layout()
plt.savefig("graficas/heatmap_http.png", dpi=150)
plt.close()
print("✓ heatmap_http.png generada")

print("\n✓ Las 3 gráficas fueron guardadas en graficas/")
