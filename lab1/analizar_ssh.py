import re
import json
from collections import defaultdict

LOG_FILE = "auth.log"
UMBRAL = 50

conteo = defaultdict(int)

with open(LOG_FILE, "r") as f:
    for linea in f:
        if "Failed password" in linea:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", linea)
            if match:
                ip = match.group(1)
                conteo[ip] += 1

# Ordenar por cantidad de intentos
ranking = sorted(conteo.items(), key=lambda x: x[1], reverse=True)
top10 = ranking[:10]

print("=" * 50)
print("TOP 10 IPs con más intentos fallidos SSH")
print("=" * 50)
for ip, intentos in top10:
    print(f"  {ip:20s} -> {intentos} intentos")
    if intentos >= UMBRAL:
        print(f"  [ALERTA] IP {ip} supera el umbral de {UMBRAL} intentos")

# Exportar JSON
reporte = {
    "total_ips": len(conteo),
    "umbral_alerta": UMBRAL,
    "top10": [{"ip": ip, "intentos": intentos, "alerta": intentos >= UMBRAL} for ip, intentos in top10]
}

with open("reporte_ssh.json", "w") as f:
    json.dump(reporte, f, indent=4)

print("\nReporte exportado: reporte_ssh.json")
