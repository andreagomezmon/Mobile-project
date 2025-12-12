# SecureCookieFactory

## Environment Setup

### Prerequisites
- Mosquitto MQTT broker installed
- Arduino IDE with PubSubClient library
- Python 3.x

---

## 1. Configure Mosquitto MQTT Broker

### Setup Steps

1. **Replace configuration file:**
   - Copy `mosquitto.conf` from this repository to your Mosquitto installation directory
   - Default location: `C:\Program Files\mosquitto\`

2. **Find your local IP address:**
   - Open Command Prompt and run: `ipconfig`
   - Look for **"Wireless LAN adapter Wi-Fi:"** section
   - Note the **IPv4 Address** (e.g., `192.168.84.98`)

3. **Start the Mosquitto broker:**
   ```powershell
   cd "C:\Program Files\mosquitto"
   .\mosquitto.exe -c "C:\Program Files\mosquitto\mosquitto.conf" -v
   ```
   The `-v` flag enables verbose output for debugging.

### Testing MQTT Connection

**Publish a test message:**
```powershell
.\mosquitto_pub.exe -h "192.168.84.98" -t test/topic -m "Hello MQTT!"
```
Replace `192.168.84.98` with your actual IPv4 address.

**Subscribe to a topic:**
```powershell
mosquitto_sub.exe -h "192.168.84.98" -t test/topic
```
This will listen for messages on the specified topic. Replace `192.168.84.98` with your IP address.


---

## 2. Configure Arduino IDE for MQTT

### Increase MQTT Packet Size

The default PubSubClient library has a small packet size limit. Follow these steps to increase it:

1. **Locate PubSubClient.h:**
   - Default path: `Documents\Arduino\libraries\PubSubClient\src\PubSubClient.h`

2. **Edit the packet size limit:**
   - Open `PubSubClient.h` in a text editor
   - Find the line:
     ```cpp
     #define MQTT_MAX_PACKET_SIZE 256
     ```
   - Change it to:
     ```cpp
     #define MQTT_MAX_PACKET_SIZE 2048
     ```
   - This allows larger messages to be transmitted (your application expects 2048 bytes)

3. **Restart Arduino IDE:**
   - Close and reopen the Arduino IDE to apply the changes

---

## 3. Running the Application

- Upload the ESP32 sketches to your devices
- Ensure Mosquitto broker is running
- The log server will automatically connect and process incoming MQTT messages

---

## 4. Project Files

### Root Level
- **README.md** - This documentation file
- **mosquitto.conf** - Configuration file for the Mosquitto MQTT broker
- **logs.csv** - Log file containing recorded MQTT messages and events
- **report.tex** - LaTeX document for project report generation

### `esp32/` Directory
Contains firmware for ESP32 devices:
- **alarm_system/** - Arduino sketch for the alarm system device that publishes sensor data and receives control commands via MQTT

### `Json/` Directory
JSON schema files for message validation:
- **envelope.schema.json** - Schema for the MQTT message envelope structure
- **payload-config.schema.json** - Schema for configuration payload messages
- **payload-emergency.schema.json** - Schema for emergency alert payloads
- **payload-presence.schema.json** - Schema for presence detection payloads
- **payload-sensor.schema.json** - Schema for sensor data payloads

### `logs_server/` Directory
Python-based logging and data processing server:
- **log_server.py** - Main server script that listens to MQTT topics and logs messages
- **plotter.py** - Utility script for visualizing logged data
- **setup/** - Setup and configuration files for the logging server
  - **requirements.txt** - Python dependencies
  - **db/** - Database initialization scripts
  - **scripts/** - Setup automation scripts
  - **src/** - Database setup modules

### `server_scripts/` Directory
Additional server utilities and configuration:
- **keys/** - Directory for storing encryption keys and certificates
- **setup/** - Server configuration and initialization files
