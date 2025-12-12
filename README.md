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
