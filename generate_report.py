from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import re
from collections import defaultdict

# ── Fecha dinámica ────────────────────────────────────────────
MESES_ES = {
    1: "enero", 2: "febrero", 3: "marzo", 4: "abril",
    5: "mayo", 6: "junio", 7: "julio", 8: "agosto",
    9: "septiembre", 10: "octubre", 11: "noviembre", 12: "diciembre"
}
now = datetime.now()
fecha_es = f"{now.day} de {MESES_ES[now.month]} de {now.year}"
hora_es  = now.strftime("%H:%M:%S")
fecha_en = now.strftime("%B %d, %Y")
hora_en  = now.strftime("%I:%M:%S %p")

# ── Parsear logs ─────────────────────────────────────────────
with open("data/auth.log", "r") as f:
    logs = f.readlines()

RE_FAILED  = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*Failed password for (?:invalid user )?(\w+) from ([\d.]+)")
RE_SUCCESS = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\w+) from ([\d.]+)")
RE_SUDO    = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*sudo:.*COMMAND=(.*)")
RE_SESSION = re.compile(r"(\w+ \d+ \d+:\d+:\d+).*session (opened|closed) for user (\w+)")

failed_by_ip   = defaultdict(int)
failed_by_user = defaultdict(int)
successful, sudo_commands, sessions = [], [], []

for line in logs:
    if m := RE_FAILED.search(line):
        failed_by_ip[m.group(3)]  += 1
        failed_by_user[m.group(2)] += 1
    elif m := RE_SUCCESS.search(line):
        successful.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
    elif m := RE_SUDO.search(line):
        sudo_commands.append({"time": m.group(1), "command": m.group(2).strip()})
    elif m := RE_SESSION.search(line):
        sessions.append({"time": m.group(1), "action": m.group(2), "user": m.group(3)})

top_ips   = sorted(failed_by_ip.items(),   key=lambda x: -x[1])[:5]
top_users = sorted(failed_by_user.items(), key=lambda x: -x[1])[:5]

# Hora del login exitoso desde los logs
login_time = successful[0]["time"] if successful else "N/A"
login_ip   = successful[0]["ip"]   if successful else "N/A"

# ── Colores ───────────────────────────────────────────────────
DARK_BG   = colors.HexColor("#1a1a2e")
ACCENT    = colors.HexColor("#e94560")
ACCENT2   = colors.HexColor("#0f3460")
LIGHT_TXT = colors.HexColor("#f0f0f0")
GRAY      = colors.HexColor("#cccccc")
WARNING   = colors.HexColor("#f5a623")
DANGER    = colors.HexColor("#e94560")

def build_report(filename, lang="es"):
    doc = SimpleDocTemplate(
        filename, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    title_style = ParagraphStyle("title",
        fontSize=22, textColor=ACCENT,
        alignment=TA_CENTER, fontName="Helvetica-Bold",
        spaceAfter=0, spaceBefore=0)

    subtitle_style = ParagraphStyle("subtitle",
        fontSize=10, textColor=GRAY,
        alignment=TA_CENTER, fontName="Helvetica",
        spaceAfter=0, spaceBefore=0)

    analyst_style = ParagraphStyle("analyst",
        fontSize=9, textColor=LIGHT_TXT,
        alignment=TA_CENTER, fontName="Helvetica",
        spaceAfter=0, spaceBefore=0)

    h2_style = ParagraphStyle("h2",
        fontSize=13, textColor=ACCENT,
        fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)

    body_style = ParagraphStyle("body",
        fontSize=9, textColor=colors.black,
        fontName="Helvetica", spaceAfter=4, leading=14)

    label_style = ParagraphStyle("label",
        fontSize=10, textColor=colors.white,
        fontName="Helvetica-Bold", alignment=TA_CENTER,
        spaceAfter=0, spaceBefore=0)

    if lang == "es":
        T = {
            "title":      "INFORME DE INCIDENTE DE SEGURIDAD",
            "subtitle":   "Operación ShadowEntry — NovaTech SRL",
            "analyst":    f"Analista: Marina Della Mattia  |  Fecha: {fecha_es}  |  Hora: {hora_es}",
            "severity":   "SEVERIDAD: CRÍTICA",
            "summary_h":  "1. RESUMEN EJECUTIVO",
            "summary":    f"El día <b>{fecha_es}</b>, el servidor de producción <b>server01</b> de NovaTech SRL sufrió un ataque de fuerza bruta SSH que resultó en acceso no autorizado. El atacante, operando desde la IP <b>{login_ip}</b>, realizó {sum(failed_by_ip.values())} intentos de autenticación antes de obtener acceso con el usuario <i>deploy</i>. Una vez dentro, escaló privilegios, accedió a credenciales del sistema y procedió a exfiltrar datos confidenciales.",
            "phase1_h":   "2. FASE 1 — RECONOCIMIENTO Y FUERZA BRUTA",
            "phase1_txt": f"Se detectaron <b>{sum(failed_by_ip.values())} intentos fallidos</b> de autenticación SSH provenientes de múltiples IPs. La IP principal realizó {failed_by_ip.get(login_ip, 847)} intentos de forma automatizada.",
            "top_ip_h":   "IPs con mayor actividad:",
            "top_usr_h":  "Usuarios más intentados:",
            "phase2_h":   "3. FASE 2 — ACCESO EXITOSO",
            "phase2_txt": f"A las <b>{login_time}</b> del {fecha_es}, el atacante logró autenticarse exitosamente con el usuario <b>deploy</b> desde la IP <b>{login_ip}</b>.",
            "phase3_h":   "4. FASE 3 — ACTIVIDAD POST-COMPROMISO",
            "phase3_txt": "Una vez dentro del sistema, el atacante ejecutó los siguientes comandos con privilegios elevados:",
            "timeline_h": "5. LÍNEA DE TIEMPO",
            "rec_h":      "6. RECOMENDACIONES",
            "recs": [
                f"Bloquear inmediatamente la IP {login_ip} en el firewall perimetral.",
                "Rotar todas las credenciales del servidor comprometido.",
                "Revisar integridad de archivos en /etc/shadow y /var/www/html/uploads.",
                "Verificar si la exfiltración via FTP fue exitosa (data.tar.gz).",
                "Deshabilitar autenticación por contraseña SSH; usar solo claves públicas.",
                "Implementar fail2ban para bloqueo automático tras intentos fallidos.",
                f"Revisar logs de FTP en busca de más conexiones desde {login_ip}.",
            ],
            "footer": f"Generado el {fecha_es} a las {hora_es}  |  Marina Della Mattia — github.com/Marudm",
        }
    else:
        T = {
            "title":      "SECURITY INCIDENT REPORT",
            "subtitle":   "Operation ShadowEntry — NovaTech SRL",
            "analyst":    f"Analyst: Marina Della Mattia  |  Date: {fecha_en}  |  Time: {hora_en}",
            "severity":   "SEVERITY: CRITICAL",
            "summary_h":  "1. EXECUTIVE SUMMARY",
            "summary":    f"On <b>{fecha_en}</b>, the production server <b>server01</b> at NovaTech SRL was targeted by an SSH brute-force attack that resulted in unauthorized access. The attacker, operating from IP <b>{login_ip}</b>, made {sum(failed_by_ip.values())} authentication attempts before gaining access with the <i>deploy</i> user account. Once inside, the attacker escalated privileges, accessed system credentials, and proceeded to exfiltrate confidential data.",
            "phase1_h":   "2. PHASE 1 — RECONNAISSANCE & BRUTE FORCE",
            "phase1_txt": f"A total of <b>{sum(failed_by_ip.values())} failed SSH authentication attempts</b> were detected from multiple source IPs. The primary attacking IP made {failed_by_ip.get(login_ip, 847)} automated attempts.",
            "top_ip_h":   "Top IPs by activity:",
            "top_usr_h":  "Most attempted usernames:",
            "phase2_h":   "3. PHASE 2 — SUCCESSFUL ACCESS",
            "phase2_txt": f"At <b>{login_time}</b> on {fecha_en}, the attacker successfully authenticated as user <b>deploy</b> from IP <b>{login_ip}</b>.",
            "phase3_h":   "4. PHASE 3 — POST-COMPROMISE ACTIVITY",
            "phase3_txt": "Once inside the system, the attacker executed the following commands with elevated privileges:",
            "timeline_h": "5. INCIDENT TIMELINE",
            "rec_h":      "6. RECOMMENDATIONS",
            "recs": [
                f"Immediately block IP {login_ip} on the perimeter firewall.",
                "Rotate all credentials on the compromised server.",
                "Check file integrity for /etc/shadow and /var/www/html/uploads.",
                "Verify whether FTP exfiltration was successful (data.tar.gz).",
                "Disable SSH password authentication; enforce public key only.",
                "Deploy fail2ban for automatic blocking after failed attempts.",
                f"Review FTP logs for additional connections from {login_ip}.",
            ],
            "footer": f"Generated on {fecha_en} at {hora_en}  |  Marina Della Mattia — github.com/Marudm",
        }

    story = []

    # ── Header: título ────────────────────────────────────────
    title_data = [[Paragraph(T["title"], title_style)]]
    title_table = Table(title_data, colWidths=[17*cm])
    title_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
    ]))
    story.append(title_table)

    # ── Header: subtítulo + analista ─────────────────────────
    sub_data = [
        [Paragraph(T["subtitle"], subtitle_style)],
        [Paragraph(T["analyst"],  analyst_style)],
    ]
    sub_table = Table(sub_data, colWidths=[17*cm])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), ACCENT2),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
    ]))
    story.append(sub_table)

    # ── Badge severidad ───────────────────────────────────────
    sev_data = [[Paragraph(T["severity"], label_style)]]
    sev_table = Table(sev_data, colWidths=[17*cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DANGER),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.5*cm))

    # ── Resumen ejecutivo ─────────────────────────────────────
    story.append(Paragraph(T["summary_h"], h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(T["summary"], body_style))
    story.append(Spacer(1, 0.3*cm))

    # ── Fase 1 ────────────────────────────────────────────────
    story.append(Paragraph(T["phase1_h"], h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(T["phase1_txt"], body_style))
    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(T["top_ip_h"], body_style))
    ip_data = [["IP", "Intentos" if lang=="es" else "Attempts", "Rol / Role"]]
    for ip, count in top_ips:
        rol = "ATACANTE PRINCIPAL / MAIN ATTACKER" if count > 100 else "Ruido / Noise"
        ip_data.append([ip, str(count), rol])
    ip_table = Table(ip_data, colWidths=[6*cm, 3*cm, 8*cm])
    ip_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f9f9f9")]),
        ("GRID",          (0,0), (-1,-1), 0.5, GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("TEXTCOLOR",     (0,1), (0,1),   DANGER),
        ("FONTNAME",      (0,1), (0,1),   "Helvetica-Bold"),
    ]))
    story.append(ip_table)
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph(T["top_usr_h"], body_style))
    usr_data = [["Usuario / User", "Intentos" if lang=="es" else "Attempts"]]
    for user, count in top_users:
        usr_data.append([user, str(count)])
    usr_table = Table(usr_data, colWidths=[8*cm, 3*cm])
    usr_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f9f9f9")]),
        ("GRID",          (0,0), (-1,-1), 0.5, GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(usr_table)
    story.append(Spacer(1, 0.3*cm))

    # ── Fase 2 ────────────────────────────────────────────────
    story.append(Paragraph(T["phase2_h"], h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(T["phase2_txt"], body_style))
    story.append(Spacer(1, 0.3*cm))

    # ── Fase 3 ────────────────────────────────────────────────
    story.append(Paragraph(T["phase3_h"], h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(T["phase3_txt"], body_style))
    story.append(Spacer(1, 0.2*cm))

    cmd_alerts = {
        "/bin/bash":   ("!", WARNING, "Privilege escalation shell"  if lang=="en" else "Shell con privilegios elevados"),
        "/etc/shadow": ("!!", DANGER, "Credential theft"            if lang=="en" else "Robo de credenciales"),
        "data.tar.gz": ("!",  WARNING,"Suspicious compression"      if lang=="en" else "Compresion sospechosa"),
        "curl":        ("!!",DANGER,  "Data exfiltration via FTP"   if lang=="en" else "Exfiltracion de datos via FTP"),
        "find":        ("i",  ACCENT2,"System reconnaissance"       if lang=="en" else "Reconocimiento del sistema"),
    }
    cmd_data = [["Hora" if lang=="es" else "Time", "Comando / Command", "Alerta / Alert"]]
    for cmd in sudo_commands:
        alert_txt = ""
        for keyword, (icon, clr, desc) in cmd_alerts.items():
            if keyword in cmd["command"]:
                alert_txt = f"{icon} {desc}"
                break
        cmd_data.append([cmd["time"], cmd["command"][:45], alert_txt])

    cmd_table = Table(cmd_data, colWidths=[3.5*cm, 8.5*cm, 5*cm])
    cmd_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,-1), "Courier"),
        ("FONTSIZE",      (0,0), (-1,-1), 7),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#fff5f5")]),
        ("GRID",          (0,0), (-1,-1), 0.5, GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(cmd_table)
    story.append(Spacer(1, 0.3*cm))

    # ── Timeline ──────────────────────────────────────────────
    story.append(Paragraph(T["timeline_h"], h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))

    all_events = []
    for s in successful:
        all_events.append((s["time"], "LOGIN",   s["ip"],   "LOGIN EXITOSO"  if lang=="es" else "SUCCESSFUL LOGIN"))
    for c in sudo_commands:
        all_events.append((c["time"], "CMD",     "",        c["command"][:55]))
    for s in sessions:
        all_events.append((s["time"], "SESSION", s["user"], f"Session {s['action']}"))

    tl_data = [["Hora/Time", "Tipo/Type", "Detalle/Detail"]]
    for evt in all_events:
        tl_data.append([evt[0], evt[1], f"{evt[3]} {evt[2]}".strip()])

    tl_table = Table(tl_data, colWidths=[3.5*cm, 2.5*cm, 11*cm])
    tl_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  DARK_BG),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7.5),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f9f9f9")]),
        ("GRID",          (0,0), (-1,-1), 0.5, GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(tl_table)
    story.append(Spacer(1, 0.3*cm))

    # ── Recomendaciones ───────────────────────────────────────
    story.append(Paragraph(T["rec_h"], h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))
    for i, rec in enumerate(T["recs"], 1):
        story.append(Paragraph(f"<b>{i}.</b> {rec}", body_style))

    story.append(Spacer(1, 0.5*cm))

    # ── Footer ────────────────────────────────────────────────
    footer_style = ParagraphStyle("footer",
        fontSize=7, textColor=LIGHT_TXT, alignment=TA_CENTER)
    footer_data = [[Paragraph(T["footer"], footer_style)]]
    footer_table = Table(footer_data, colWidths=[17*cm])
    footer_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(footer_table)

    doc.build(story)
    print(f"Reporte generado: {filename}")

import os
os.makedirs("report", exist_ok=True)
build_report("report/reporte_es.pdf", lang="es")
build_report("report/report_en.pdf",  lang="en")