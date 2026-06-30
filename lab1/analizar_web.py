import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "access.log"

peticiones = defaultdict(list)
errores = defaultdict(lambda: defaultdict(int))
sqli_patterns = ["union", "select", "--", "or 1=1", "'", "drop", "insert", "sleep("]

sqli_detectados = []

with open(LOG_FILE, "r") as f:
    for linea in f:
        match = re.match(r'(\S+) \S+ \S+ \[(.+?)\] "(\S+) (\S+) \S+" (\d+) \S+', linea)
        if not match:
            continue
        ip, fecha_str, metodo, url, codigo = match.groups()
        try:
            fecha = datetime.strptime(fecha_str[:20], "%d/%b/%Y:%H:%M:%S")
        except:
            continue
        peticiones[ip].append(fecha)
        if codigo.startswith("4") or codigo.startswith("5"):
            errores[ip][codigo] += 1
        url_lower = url.lower()
        for patron in sqli_patterns:
            if patron in url_lower:
                sqli_detectados.append({"ip": ip, "url": url, "patron": patron})
                break

# Detectar escaneo de directorios
print("=" * 55)
print("DETECCION DE ESCANEO DE DIRECTORIOS (>20 rutas en <60s)")
print("=" * 55)
escaneadores = []
for ip, tiempos in peticiones.items():
    tiempos_sorted = sorted(tiempos)
    for i in range(len(tiempos_sorted)):
        ventana = [t for t in tiempos_sorted[i:] if (t - tiempos_sorted[i]).seconds <= 60]
        if len(ventana) >= 20:
            escaneadores.append({"ip": ip, "peticiones_en_60s": len(ventana)})
            print(f"  [ALERTA ESCANEO] {ip} -> {len(ventana)} peticiones en 60 seg")
            break

# Top errores 4xx/5xx
print("\n" + "=" * 55)
print("TOP IPs con errores 4xx/5xx")
print("=" * 55)
top_errores = sorted(errores.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]
for ip, codigos in top_errores:
    total = sum(codigos.values())
    print(f"  {ip:20s} -> {total} errores {dict(codigos)}")

# SQLi
print("\n" + "=" * 55)
print(f"INTENTOS DE SQL INJECTION DETECTADOS: {len(sqli_detectados)}")
print("=" * 55)
for s in sqli_detectados[:10]:
    print(f"  IP: {s['ip']} | Patron: {s['patron']} | URL: {s['url'][:60]}")

# Exportar JSON
reporte = {
    "escaneo_directorios": escaneadores,
    "top10_errores": [{"ip": ip, "codigos": dict(cod)} for ip, cod in top_errores],
    "sqli_detectados": len(sqli_detectados),
    "sqli_muestra": sqli_detectados[:10]
}
with open("reporte_web.json", "w") as f:
    json.dump(reporte, f, indent=4)

print("\nReporte exportado: reporte_web.json")
