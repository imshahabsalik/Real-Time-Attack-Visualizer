# 🔐 Real-Time Windows Threat Detection Dashboard

A real-time cybersecurity project that detects and visualizes failed login attempts using Windows Event Logs.

## 🚀 Features
- Real-time monitoring of Windows Security Logs
- Detects Event ID 4625 & 4776 (failed logins)
- Live dashboard using Flask + Socket.IO
- Attack simulation using Kali Linux
- Graph visualization of login attempts

## 🧠 Tech Stack
- Python (Flask, SocketIO, pywin32)
- Windows Event Logs
- HTML, JavaScript (Chart.js)
- Kali Linux (attack simulation)

## ⚡ How it Works
1. Windows logs failed login attempts
2. Python reads logs in real-time
3. Data is sent via WebSocket
4. Dashboard updates instantly

## 🧪 Attack Simulation
From Kali:
```bash
smbclient -L <target-ip> -U username%wrongpass
