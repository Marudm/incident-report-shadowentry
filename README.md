# 🔍 Incident Report — Operación ShadowEntry

![Security](https://img.shields.io/badge/Security-Incident%20Response-red)
![Python](https://img.shields.io/badge/Python-3.13-blue)
![Status](https://img.shields.io/badge/Status-Completed-green)

## 📋 Descripción / Description

**ES:** Análisis forense completo de un incidente de seguridad real simulado. 
El servidor de producción **server01** de NovaTech SRL sufrió un ataque de 
fuerza bruta SSH que resultó en acceso no autorizado, escalada de privilegios 
y exfiltración de datos confidenciales.

**EN:** Full forensic analysis of a simulated real-world security incident.
Production server **server01** at NovaTech SRL was targeted by an SSH brute-force
attack resulting in unauthorized access, privilege escalation, and data exfiltration.

---

## 🚨 Resumen del Incidente / Incident Summary

| | |
|---|---|
| **Fecha / Date** | 15 de Noviembre 2024 |
| **Severidad / Severity** | 🔴 CRÍTICA / CRITICAL |
| **Vector de ataque / Attack vector** | SSH Brute Force |
| **IP Atacante / Attacker IP** | 185.220.101.47 |
| **Intentos fallidos / Failed attempts** | 847 |
| **Usuario comprometido / Compromised user** | deploy |
| **Impacto / Impact** | Credential theft + Data exfiltration |

---

## 🔬 Metodología / Methodology

### Fases del ataque detectadas / Attack phases detected:
1. **Reconocimiento** — Ruido de fondo desde múltiples IPs
2. **Fuerza bruta** — 847 intentos automatizados en 36 minutos
3. **Acceso exitoso** — Login con usuario `deploy` a las 04:23:11
4. **Escalada de privilegios** — Shell root via sudo
5. **Reconocimiento interno** — Búsqueda de archivos .conf
6. **Robo de credenciales** — Lectura de `/etc/shadow`
7. **Exfiltración** — Compresión y envío vía FTP

---

## 🛠️ Stack Técnico / Tech Stack

- **Python 3.13** — Parsing y análisis de logs
- **Regex** — Detección de patrones de ataque
- **ReportLab** — Generación de reportes PDF profesionales
- **Log Analysis** — Técnicas equivalentes a SIEM básico

---

## 📁 Estructura del proyecto / Project structure

---

## 🛡️ Recomendaciones implementadas / Implemented recommendations

1. Bloquear IP `185.220.101.47` en firewall perimetral
2. Rotar todas las credenciales del servidor comprometido
3. Verificar integridad de `/etc/shadow` y `/var/www/html/uploads`
4. Deshabilitar autenticación SSH por contraseña — usar solo claves públicas
5. Implementar `fail2ban` para bloqueo automático
6. Revisar logs FTP en busca de conexiones adicionales

---

## 👩‍💻 Autora / Author

**Marina Della Mattia**  
Analista en Sistemas | Ciberseguridad Blue Team  
[GitHub](https://github.com/Marudm) · [LinkedIn](https://www.linkedin.com/in/marinadellamattia/)