import csv
import json
from collections import defaultdict
from datetime import datetime

import matplotlib.pyplot as plt

LOG_FILE = "logs.csv"
TIME_FMT = "%Y-%m-%d %H:%M:%S"

# data[room][device]["ts"|"temp"|"hum"]
data = defaultdict(lambda: defaultdict(lambda: {"ts": [], "temp": [], "hum": []}))

with open(LOG_FILE, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get("type") != "SENSOR":
            continue

        room = row["room_id"]
        dev = row["device_id"]

        ts = datetime.strptime(row["timestamp"], TIME_FMT)
        payload = json.loads(row["payload_json"])

        t = payload.get("temp")
        h = payload.get("humidity")

        if t is None or h is None:
            continue

        # Visualization-only sanity filter (optional)
        if not (-10 <= float(t) <= 60 and 0 <= float(h) <= 100):
            continue

        data[room][dev]["ts"].append(ts)
        data[room][dev]["temp"].append(float(t))
        data[room][dev]["hum"].append(float(h))

if not data:
    raise SystemExit("No SENSOR data found")

# One figure per room
for room_id, devices in data.items():
    fig, (ax_temp, ax_hum) = plt.subplots(2, 1, sharex=True, figsize=(10, 6))

    # Temperature subplot
    for dev_id, series in devices.items():
        if series["ts"]:
            ax_temp.plot(series["ts"], series["temp"], label=dev_id)
    ax_temp.set_title(f"Sensor data over time | {room_id}")
    ax_temp.set_ylabel("Temperature (°C)")
    ax_temp.grid(True)
    ax_temp.legend(title="Device")

    # Humidity subplot
    for dev_id, series in devices.items():
        if series["ts"]:
            ax_hum.plot(series["ts"], series["hum"], label=dev_id)
    ax_hum.set_ylabel("Humidity (%)")
    ax_hum.set_xlabel("Time")
    ax_hum.grid(True)
    ax_hum.legend(title="Device")

    fig.tight_layout()

plt.show()
