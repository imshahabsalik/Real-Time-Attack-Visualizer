from flask import Flask, render_template
from flask_socketio import SocketIO
import win32evtlog
import threading
import time
import re

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

log_type = 'Security'
server = 'localhost'

failed_count = 0


# 🔍 Extract IP from log
def extract_ip(message):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
    return match.group(1) if match else "Unknown"


# 📡 Read Windows logs in real-time
def read_logs():
    global failed_count

    hand = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    seen = set()

    print("🚀 Monitoring started...")

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        if events:
            for event in events:

                event_id = event.EventID & 0xFFFF

                # avoid duplicates
                if event.RecordNumber in seen:
                    continue

                seen.add(event.RecordNumber)

                print("Event:", event_id)

                if event_id == 4625 or event_id == 4776:
                    failed_count += 1

                    message = " ".join(event.StringInserts) if event.StringInserts else ""
                    ip = extract_ip(message)

                    print("🚨 DETECTED FAILED LOGIN from:", ip)

                    socketio.emit('new_event', {
                        "count": failed_count,
                        "time": str(event.TimeGenerated),
                        "ip": ip
                    })

        time.sleep(2)


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    t = threading.Thread(target=read_logs)
    t.daemon = True
    t.start()

    socketio.run(app, host='0.0.0.0', port=5000)