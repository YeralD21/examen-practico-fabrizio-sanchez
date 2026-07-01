import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "auth.log"
UMBRAL = 50

conteo = defaultdict(int)
total_intentos = 0

with open(LOG_FILE, "r") as f:
    for linea in f:
        if "Failed password" in linea:
            total_intentos += 1
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", linea)
            if match:
                ip = match.group(1)
                conteo[ip] += 1

ranking = sorted(conteo.items(), key=lambda x: x[1], reverse=True)
top10 = ranking[:10]

print("=" * 50)
print("TOP 10 IPs con más intentos fallidos SSH")
print("=" * 50)
for ip, intentos in top10:
    print(f"  {ip:20s} -> {intentos} intentos")
    if intentos >= UMBRAL:
        print(f"  [ALERTA] IP: {ip} — {intentos} intentos fallidos — Posible ataque de fuerza bruta")

reporte = {
    "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total_intentos_fallidos": total_intentos,
    "ips_sospechosas": [
        {
            "ip": ip,
            "intentos": intentos,
            "alerta": intentos >= UMBRAL
        }
        for ip, intentos in top10
    ]
}

with open("reporte_ssh.json", "w") as f:
    json.dump(reporte, f, indent=4)

print("\nReporte exportado: reporte_ssh.json")
