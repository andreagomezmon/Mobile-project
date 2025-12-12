import csv
from datetime import datetime
import matplotlib.pyplot as plt

timestamps = []
temps = []
hums = []

with open("logs.csv", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["type"] == "SENSOR":
            ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            payload = eval(row["payload_json"])  # safe enough for lab CSV
            timestamps.append(ts)
            temps.append(payload["temp"])
            hums.append(payload["humidity"])

plt.figure()
plt.plot(timestamps, temps, label="Temperature (°C)")
plt.plot(timestamps, hums, label="Humidity (%)")
plt.xlabel("Time")
plt.ylabel("Value")
plt.title("Sensor data over time")
plt.legend()
plt.grid(True)
plt.show()
