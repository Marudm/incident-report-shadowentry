import re
from collections import defaultdict
from datetime import datetime

# ── Cargar logs ──────────────────────────────────────────────
with open("data/auth.log", "r") as f:
    logs = f.readlines()

print(f"📂 Total de líneas analizadas: {len(logs)}\n")

# ── Patrones regex ───────────────────────────────────────────
RE_FAILED  = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from ([\d.]+)")
RE_SUCCESS = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\w+) from ([\d.]+)")
RE_SUDO    = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*sudo:.*COMMAND=(.*)")
RE_SESSION = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*session (opened|closed) for user (\w+)")

# ── Estructuras de datos ─────────────────────────────────────
failed_by_ip    = defaultdict(int)
failed_by_user  = defaultdict(int)
successful      = []
sudo_commands   = []
sessions        = []

# ── Parsear ──────────────────────────────────────────────────
for line in logs:
    if m := RE_FAILED.search(line):
        failed_by_ip[m.group(3)]   += 1
        failed_by_user[m.group(2)] += 1
    elif m := RE_SUCCESS.search(line):
        successful.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
    elif m := RE_SUDO.search(line):
        sudo_commands.append({"time": m.group(1), "command": m.group(2).strip()})
    elif m := RE_SESSION.search(line):
        sessions.append({"time": m.group(1), "action": m.group(2), "user": m.group(3)})

# ── Reporte en consola ───────────────────────────────────────
print("=" * 60)
print("   INCIDENT REPORT - OPERACIÓN SHADOWENTRY")
print("   NovaTech SRL | Analista: Marina Della Mattia")
print("=" * 60)

print("\n🔴 FASE 1 — RECONOCIMIENTO Y FUERZA BRUTA")
print(f"   Total intentos fallidos: {sum(failed_by_ip.values())}")
print("\n   Top 5 IPs atacantes:")
for ip, count in sorted(failed_by_ip.items(), key=lambda x: -x[1])[:5]:
    flag = " ⚠️  ATACANTE PRINCIPAL" if count > 100 else ""
    print(f"   {ip:20s} → {count:4d} intentos{flag}")

print("\n   Top 5 usuarios intentados:")
for user, count in sorted(failed_by_user.items(), key=lambda x: -x[1])[:5]:
    print(f"   {user:20s} → {count:4d} intentos")

print("\n🟡 FASE 2 — ACCESO EXITOSO")
if successful:
    for s in successful:
        print(f"   ✅ Login exitoso: usuario '{s['user']}' desde {s['ip']} a las {s['time']}")
else:
    print("   No se detectaron logins exitosos.")

print("\n🔴 FASE 3 — ACTIVIDAD POST-COMPROMISO")
if sudo_commands:
    print("   Comandos ejecutados con privilegios elevados:")
    for cmd in sudo_commands:
        alert = ""
        if "shadow" in cmd["command"]:
            alert = "  ⚠️  LECTURA DE CREDENCIALES"
        elif "curl" in cmd["command"] or "ftp" in cmd["command"]:
            alert = "  🚨 POSIBLE EXFILTRACIÓN DE DATOS"
        elif "tar" in cmd["command"]:
            alert = "  ⚠️  COMPRESIÓN DE ARCHIVOS SOSPECHOSA"
        print(f"   [{cmd['time']}] {cmd['command']}{alert}")
else:
    print("   No se detectaron comandos sudo.")

print("\n📋 LÍNEA DE TIEMPO DEL INCIDENTE:")
all_events = []
for s in successful:
    all_events.append((s["time"], f"LOGIN EXITOSO - usuario '{s['user']}' desde {s['ip']}"))
for c in sudo_commands:
    all_events.append((c["time"], f"COMANDO PRIVILEGIADO - {c['command'][:50]}"))
for s in sessions:
    all_events.append((s["time"], f"SESIÓN {s['action'].upper()} - usuario '{s['user']}'"))

for time, event in all_events:
    print(f"   {time} → {event}")

print("\n🛡️  RECOMENDACIONES:")
print("   1. Bloquear IP 185.220.101.47 en firewall inmediatamente")
print("   2. Cambiar todas las credenciales del servidor")
print("   3. Revisar archivos accedidos: /etc/shadow, /var/www/html/uploads")
print("   4. Verificar si data.tar.gz fue exfiltrado exitosamente")
print("   5. Implementar autenticación por clave SSH (deshabilitar passwords)")
print("   6. Configurar fail2ban para bloqueo automático por fuerza bruta")
print("\n" + "=" * 60)