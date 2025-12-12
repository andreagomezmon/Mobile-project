#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <ArduinoJson.h>

extern "C" {
  #include "mbedtls/aes.h"
  #include "mbedtls/md.h"
  #include "mbedtls/base64.h"
}



// =======================
// Peer limits
// =======================
#define MAX_PEERS 4

// =======================
// Hardware configuration
// =======================

#define DHT_SENSOR_PIN  26
#define DHT_SENSOR_TYPE DHT11
#define LED_WHITE_PIN   33
#define LED_RED_PIN     32
#define BUTTON_PIN      27

DHT dht_sensor(DHT_SENSOR_PIN, DHT_SENSOR_TYPE);

// =======================
// WiFi / MQTT configuration
// =======================
const char *WIFI_SSID = "Proximus-Home-4C40";//"AndroidAnd"; // // "WiFi-2.4-6B6A"; // Enter your WiFi name
const char *WIFI_PASSWORD = "wrdhjmnbbmfxr";//= "qddd8243";// // "45dVAWr42yEv";  // Enter WiFi password

// MQTT Broker
const char *MQTT_HOST = "192.168.1.20";//" 192.168.84.98";// "broker.emqx.io";
const int MQTT_PORT = 1883;
const char *mqtt_username = ""; //"emqx";
const char *mqtt_password = ""; //"public";

// Identity for this device
const char *ROOM_ID   = "Room1";
const char *DEVICE_ID = "D001";

// Topics (room-specific)
String topicRoom;      // e.g. "factory/Room1"
String topicPresence;  // e.g. "factory/Room1/presence"

WiFiClient espClient;
PubSubClient mqttClient(espClient);

bool sentOnlineThisSession = false;
unsigned long lastReconnectAttemptMs = 0;
const unsigned long RECONNECT_BACKOFF_MS = 2000;

bool lastButton = HIGH;
bool buttonArmed = false;
unsigned long bootMs = 0;



// =======================
// Crypto configuration
// =======================

// 16-byte AES key (example). Replace with your room key.
static const uint8_t K_ENC[16] = {
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
};

// 32-byte HMAC key (example). Replace with your room key.
static const uint8_t K_MAC[32] = {
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02
};

// Sequence number for this device
uint32_t seqCounter = 0;

// =======================
// State for logic
// =======================

float localTemp   = 0.0f;
float localHum    = 0.0f;
float remoteTemp  = 0.0f;
float remoteHum   = 0.0f;
bool  peerOnline  = false;
bool  haveRemote  = false;

unsigned long lastSensorSend = 0;

// Thresholds (can be updated via CONFIG if you want)
float TEMP_MIN = 18.0f;
float TEMP_MAX = 28.0f;
float HUM_MIN  = 30.0f;
float HUM_MAX  = 60.0f;


// =======================
// Peer definitions
// =======================
struct PeerState {
  char deviceId[16];
  bool online;
  bool haveSensor;
  float temp;
  float hum;
  uint32_t lastSeq;
  bool initialized;
};

PeerState peers[MAX_PEERS];
uint8_t peerCount = 0;

// =======================
// Simple inbound rate limiting (DoS mitigation)
// =======================

unsigned long inboundWindowStartMs = 0;
uint16_t inboundCountInWindow = 0;
const uint16_t MAX_INBOUND_PER_SECOND = 20;  // adjust as desired

// =======================
// Utility functions
// =======================

void connectWiFi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected, IP: " + WiFi.localIP().toString());
}

void generateRandomIV(uint8_t iv[16]) {
  // Simple random IV: 16 bytes from esp_random
  for (int i = 0; i < 4; i++) {
    uint32_t r = esp_random();
    iv[i*4 + 0] = (r >> 24) & 0xFF;
    iv[i*4 + 1] = (r >> 16) & 0xFF;
    iv[i*4 + 2] = (r >> 8)  & 0xFF;
    iv[i*4 + 3] = (r >> 0)  & 0xFF;
  }
}

bool pkcs7Pad(const uint8_t *input, size_t inLen, uint8_t **outBuf, size_t *outLen) {
  size_t blockSize = 16;
  size_t padLen = blockSize - (inLen % blockSize);
  if (padLen == 0) padLen = blockSize;
  *outLen = inLen + padLen;
  *outBuf = (uint8_t*)malloc(*outLen);
  if (!*outBuf) return false;
  memcpy(*outBuf, input, inLen);
  for (size_t i = 0; i < padLen; i++) {
    (*outBuf)[inLen + i] = (uint8_t)padLen;
  }
  return true;
}

bool pkcs7Unpad(uint8_t *buf, size_t inLen, size_t *outLen) {
  if (inLen == 0) return false;
  uint8_t padLen = buf[inLen - 1];
  if (padLen == 0 || padLen > 16 || padLen > inLen) return false;
  for (size_t i = 0; i < padLen; i++) {
    if (buf[inLen - 1 - i] != padLen) return false;
  }
  *outLen = inLen - padLen;
  return true;
}

bool aesCbcEncrypt(const uint8_t *plaintext, size_t plainLen,
                   const uint8_t iv[16],
                   uint8_t **cipherOut, size_t *cipherLen) {
  uint8_t *padded = nullptr;
  size_t paddedLen = 0;
  if (!pkcs7Pad(plaintext, plainLen, &padded, &paddedLen)) {
    return false;
  }

  *cipherOut = (uint8_t*)malloc(paddedLen);
  if (!*cipherOut) {
    free(padded);
    return false;
  }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, K_ENC, 128);

  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, 16);

  int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, paddedLen,
                                  ivCopy, padded, *cipherOut);

  mbedtls_aes_free(&ctx);
  free(padded);

  if (ret != 0) {
    free(*cipherOut);
    *cipherOut = nullptr;
    return false;
  }
  *cipherLen = paddedLen;
  return true;
}

bool aesCbcDecrypt(const uint8_t *cipher, size_t cipherLen,
                   const uint8_t iv[16],
                   uint8_t **plainOut, size_t *plainLen) {
  *plainOut = (uint8_t*)malloc(cipherLen);
  if (!*plainOut) return false;

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, K_ENC, 128);

  uint8_t ivCopy[16];
  memcpy(ivCopy, iv, 16);

  int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, cipherLen,
                                  ivCopy, cipher, *plainOut);

  mbedtls_aes_free(&ctx);
  if (ret != 0) {
    free(*plainOut);
    *plainOut = nullptr;
    return false;
  }

  size_t unpaddedLen;
  if (!pkcs7Unpad(*plainOut, cipherLen, &unpaddedLen)) {
    free(*plainOut);
    *plainOut = nullptr;
    return false;
  }

  *plainLen = unpaddedLen;
  return true;
}

bool computeHmac(const uint8_t *header, size_t headerLen,
                 const uint8_t *cipher, size_t cipherLen,
                 uint8_t outMac[32]) {
  const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!mdInfo) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, mdInfo, 1) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }

  mbedtls_md_hmac_starts(&ctx, K_MAC, sizeof(K_MAC));
  mbedtls_md_hmac_update(&ctx, header, headerLen);
  mbedtls_md_hmac_update(&ctx, cipher, cipherLen);
  mbedtls_md_hmac_finish(&ctx, outMac);
  mbedtls_md_free(&ctx);
  return true;
}

bool base64Encode(const uint8_t *input, size_t inLen, String &out) {
  size_t outLen = 0;
  // Query required length
  if (mbedtls_base64_encode(nullptr, 0, &outLen, input, inLen) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    return false;
  }
  uint8_t *buf = (uint8_t*)malloc(outLen);
  if (!buf) return false;

  size_t actualLen = 0;
  int ret = mbedtls_base64_encode(buf, outLen, &actualLen, input, inLen);
  if (ret != 0) {
    free(buf);
    return false;
  }
  out = "";
  for (size_t i = 0; i < actualLen; i++) {
    out += (char)buf[i];
  }
  free(buf);
  return true;
}

bool base64Decode(const String &in, uint8_t **outBuf, size_t *outLen) {
  size_t outSize = 0;
  int ret = mbedtls_base64_decode(nullptr, 0, &outSize,
                                  (const uint8_t*)in.c_str(), in.length());
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    return false;
  }
  *outBuf = (uint8_t*)malloc(outSize);
  if (!*outBuf) return false;

  size_t actualLen = 0;
  ret = mbedtls_base64_decode(*outBuf, outSize, &actualLen,
                              (const uint8_t*)in.c_str(), in.length());
  if (ret != 0) {
    free(*outBuf);
    *outBuf = nullptr;
    return false;
  }
  *outLen = actualLen;
  return true;
}

bool isOutOfRange(float t, float h) {
  return (t < TEMP_MIN || t > TEMP_MAX ||
          h < HUM_MIN  || h > HUM_MAX);
}

// =======================
// Secure send helpers
// =======================

void buildHeader(const char *deviceId, const char *roomId,
                 const char *typeStr, uint32_t seq,
                 const uint8_t iv[16],
                 uint8_t **headerOut, size_t *headerLen) {
  String s = "";
  s += deviceId;
  s += roomId;
  s += typeStr;
  s += String(seq);

  size_t strLen = s.length();
  *headerLen = strLen + 16;
  *headerOut = (uint8_t*)malloc(*headerLen);
  memcpy(*headerOut, s.c_str(), strLen);
  memcpy(*headerOut + strLen, iv, 16);
}

// Generic secure send
void sendSecureMessage(const char *typeStr,
                       const String &plaintextJson,
                       const char *topic,
                       bool retain)  {
  seqCounter++;

  // 1) IV
  uint8_t iv[16];
  generateRandomIV(iv);

  // 2) Encrypt plaintext with AES-CBC + PKCS7
  const uint8_t *plainBytes = (const uint8_t*)plaintextJson.c_str();
  size_t plainLen = plaintextJson.length();

  uint8_t *cipherBuf = nullptr;
  size_t cipherLen = 0;
  if (!aesCbcEncrypt(plainBytes, plainLen, iv, &cipherBuf, &cipherLen)) {
    Serial.println("Encryption failed");
    return;
  }

  // 3) Build header and compute HMAC
  uint8_t *headerBuf = nullptr;
  size_t headerLen = 0;
  buildHeader(DEVICE_ID, ROOM_ID, typeStr, seqCounter, iv, &headerBuf, &headerLen);

  uint8_t mac[32];
  if (!computeHmac(headerBuf, headerLen, cipherBuf, cipherLen, mac)) {
    Serial.println("HMAC compute failed");
    free(headerBuf);
    free(cipherBuf);
    return;
  }

  // 4) Base64 encode iv, cipher, mac
  String ivB64, cipherB64, macB64;
  if (!base64Encode(iv, 16, ivB64) ||
      !base64Encode(cipherBuf, cipherLen, cipherB64) ||
      !base64Encode(mac, 32, macB64)) {
    Serial.println("Base64 encode failed");
    free(headerBuf);
    free(cipherBuf);
    return;
  }

  free(headerBuf);
  free(cipherBuf);

  // 5) Build envelope JSON
  String msg = "{";
  msg += "\"device_id\":\""; msg += DEVICE_ID; msg += "\",";
  msg += "\"room_id\":\"";   msg += ROOM_ID;   msg += "\",";
  msg += "\"type\":\"";      msg += typeStr;   msg += "\",";
  msg += "\"seq\":";         msg += String(seqCounter); msg += ",";
  msg += "\"iv\":\"";        msg += ivB64;     msg += "\",";
  msg += "\"cipher\":\"";    msg += cipherB64; msg += "\",";
  msg += "\"mac\":\"";       msg += macB64;    msg += "\"";
  msg += "}";

  // 6) Publish
  mqttClient.publish(topic, msg.c_str(), retain);
  Serial.print("Published "); Serial.print(typeStr);
  Serial.print(" to "); Serial.println(topic);
}

// Peer helpers
PeerState* getPeer(const char* deviceId) {
  for (int i = 0; i < peerCount; i++) {
    if (strcmp(peers[i].deviceId, deviceId) == 0) {
      return &peers[i];
    }
  }

  if (peerCount >= MAX_PEERS) return nullptr;

  PeerState* p = &peers[peerCount++];
  strncpy(p->deviceId, deviceId, sizeof(p->deviceId) - 1);
  p->deviceId[sizeof(p->deviceId) - 1] = '\0';
  p->online = false;
  p->haveSensor = false;
  p->initialized = true;
  p->lastSeq = 0;
  return p;
}

bool isAnyPeerOnline() {
  for (int i = 0; i < peerCount; i++) {
    if (peers[i].online) return true;
  }
  return false;
}

bool isAnyPeerBad() {
  for (int i = 0; i < peerCount; i++) {
    if (peers[i].online && peers[i].haveSensor) {
      if (isOutOfRange(peers[i].temp, peers[i].hum)) {
        return true;
      }
    }
  }
  return false;
}


// PRESENCE helpers

void sendPresenceOnline() {
  String payload = "{\"status\":\"ONLINE\"}";
  sendSecureMessage("PRESENCE", payload, topicPresence.c_str(), true);
}

void sendPresenceOfflineLWT(String &outLwtJson) {
  // This is used to build the LWT payload once at setup
  uint32_t lwtSeq = 0; // fixed seq for LWT

  uint8_t iv[16];
  generateRandomIV(iv);

  String plaintextJson = "{\"status\":\"OFFLINE\"}";
  const uint8_t *plainBytes = (const uint8_t*)plaintextJson.c_str();
  size_t plainLen = plaintextJson.length();

  uint8_t *cipherBuf = nullptr;
  size_t cipherLen = 0;
  if (!aesCbcEncrypt(plainBytes, plainLen, iv, &cipherBuf, &cipherLen)) {
    Serial.println("LWT encryption failed");
    return;
  }

  uint8_t *headerBuf = nullptr;
  size_t headerLen = 0;
  buildHeader(DEVICE_ID, ROOM_ID, "PRESENCE", lwtSeq, iv, &headerBuf, &headerLen);

  uint8_t mac[32];
  if (!computeHmac(headerBuf, headerLen, cipherBuf, cipherLen, mac)) {
    Serial.println("LWT HMAC failed");
    free(headerBuf);
    free(cipherBuf);
    return;
  }

  String ivB64, cipherB64, macB64;
  if (!base64Encode(iv, 16, ivB64) ||
      !base64Encode(cipherBuf, cipherLen, cipherB64) ||
      !base64Encode(mac, 32, macB64)) {
    Serial.println("LWT base64 failed");
    free(headerBuf);
    free(cipherBuf);
    return;
  }

  free(headerBuf);
  free(cipherBuf);

  String msg = "{";
  msg += "\"device_id\":\""; msg += DEVICE_ID; msg += "\",";
  msg += "\"room_id\":\"";   msg += ROOM_ID;   msg += "\",";
  msg += "\"type\":\"PRESENCE\",";
  msg += "\"seq\":";         msg += String(lwtSeq); msg += ",";
  msg += "\"iv\":\"";        msg += ivB64;     msg += "\",";
  msg += "\"cipher\":\"";    msg += cipherB64; msg += "\",";
  msg += "\"mac\":\"";       msg += macB64;    msg += "\"";
  msg += "}";

  outLwtJson = msg;
}

// =======================
// MQTT receive / filtering
// =======================

void processPlaintextPayload(const char *typeStr, const JsonDocument &innerDoc, const char *senderId) {
  if (strcmp(typeStr, "SENSOR") == 0) {
    PeerState* p = getPeer(senderId);
    if (!p) return;

    p->temp = innerDoc["temp"].as<float>();
    p->hum  = innerDoc["humidity"].as<float>();
    p->haveSensor = true;
  } else if (strcmp(typeStr, "EMERGENCY") == 0) {
    const char *status = innerDoc["status"] | "";
    if (strcmp(status, "EMERGENCY") == 0) {
      Serial.print("Remote EMERGENCY from ");
      Serial.println(senderId);
      digitalWrite(LED_RED_PIN, HIGH);
    }
  } else if (strcmp(typeStr, "PRESENCE") == 0) {
    PeerState* p = getPeer(senderId);
    if (!p) return;

    const char* status = innerDoc["status"] | "";
    if (strcmp(status, "ONLINE") == 0) {
      p->online = true;
    } else if (strcmp(status, "OFFLINE") == 0) {
      p->online = false;
      p->haveSensor = false;
    }
  } else if (strcmp(typeStr, "CONFIG") == 0) {
    // Optional: only accept CONFIG from a trusted admin device
    // For now accept any valid CONFIG for demo
    if (innerDoc.containsKey("temp_min")) TEMP_MIN = innerDoc["temp_min"].as<float>();
    if (innerDoc.containsKey("temp_max")) TEMP_MAX = innerDoc["temp_max"].as<float>();
    if (innerDoc.containsKey("humidity_min")) HUM_MIN = innerDoc["humidity_min"].as<float>();
    if (innerDoc.containsKey("humidity_max")) HUM_MAX = innerDoc["humidity_max"].as<float>();

    Serial.println("CONFIG updated thresholds:");
    Serial.print("TEMP_MIN="); Serial.println(TEMP_MIN);
    Serial.print("TEMP_MAX="); Serial.println(TEMP_MAX);
    Serial.print("HUM_MIN=");  Serial.println(HUM_MIN);
    Serial.print("HUM_MAX=");  Serial.println(HUM_MAX);
  }
}

void updateWhiteLed() {
  if (WiFi.status() != WL_CONNECTED || !mqttClient.connected()) {
    digitalWrite(LED_WHITE_PIN, LOW);
    return;
  }

  bool localBad = isOutOfRange(localTemp, localHum);
  bool degraded;

  if (peerCount == 0) {
    // Standalone mode
    degraded = localBad;
  } else {
    // Cooperative mode
    degraded = localBad ||
               !isAnyPeerOnline() ||
               isAnyPeerBad();
  }

  if (degraded) {
    static unsigned long lastToggle = 0;
    static bool ledState = false;
    if (millis() - lastToggle > 500) {
      lastToggle = millis();
      ledState = !ledState;
      digitalWrite(LED_WHITE_PIN, ledState ? HIGH : LOW);
    }
  } else {
    digitalWrite(LED_WHITE_PIN, HIGH);
  }
}


void mqttCallback(char *topic, byte *payload, unsigned int length) {
  // 0. Simple inbound rate limiting (per second)
  unsigned long now = millis();
  if (now - inboundWindowStartMs > 1000) {
    inboundWindowStartMs = now;
    inboundCountInWindow = 0;
  }
  inboundCountInWindow++;
  if (inboundCountInWindow > MAX_INBOUND_PER_SECOND) {
    Serial.println("Inbound rate limit exceeded, dropping MQTT message");
    return;
  }

  // 1. Basic size limit
  if (length > 2048) {
    Serial.println("MQTT payload too large");
    return;
  }

  // 2. Parse outer JSON
  StaticJsonDocument<512> doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if (err) {
    Serial.println("Outer JSON parse failed");
    return;
  }

  const char *roomId   = doc["room_id"]   | "";
  const char *deviceId = doc["device_id"] | "";
  const char *typeStr  = doc["type"]      | "";
  uint32_t    seq      = doc["seq"]       | 0;

  // Room filtering
  if (strcmp(roomId, ROOM_ID) != 0) {
    return; // wrong room
  }
  // Ignore own messages
  if (strcmp(deviceId, DEVICE_ID) == 0) {
    return;
  }

  // Type check
  if (strcmp(typeStr, "SENSOR") != 0 &&
      strcmp(typeStr, "EMERGENCY") != 0 &&
      strcmp(typeStr, "PRESENCE") != 0 &&
      strcmp(typeStr, "CONFIG") != 0) {
    return;
  }

  // 3. Replay protection (drop old or duplicate seq)
  //    PRESENCE with seq == 0 is reserved for LWT and always allowed.
  /*if (!(strcmp(typeStr, "PRESENCE") == 0 && seq == 0)) {
    if (!peerReplay.initialized || strcmp(peerReplay.deviceId, deviceId) != 0) {
      // First time we see this peer (or peer changed): initialize state
      strncpy(peerReplay.deviceId, deviceId, sizeof(peerReplay.deviceId) - 1);
      peerReplay.deviceId[sizeof(peerReplay.deviceId) - 1] = '\0';
      peerReplay.lastSeq = seq;
      peerReplay.initialized = true;
    } else {
      // Same peer: enforce strictly increasing sequence number
      if (seq <= peerReplay.lastSeq) {
        Serial.print("Replay / out-of-order message from ");
        Serial.print(deviceId);
        Serial.print(": seq=");
        Serial.print(seq);
        Serial.print(" lastSeq=");
        Serial.println(peerReplay.lastSeq);
        return;  // DROP message before any crypto
      }
      peerReplay.lastSeq = seq;
    }
  }*/

  PeerState* p = getPeer(deviceId);
  if (!p) return;

  // PRESENCE seq == 0 allowed (LWT)
  if (!(strcmp(typeStr, "PRESENCE") == 0 && seq == 0)) {
    if (p->lastSeq != 0 && seq <= p->lastSeq) {
      Serial.println("Replay / out-of-order message dropped");
      return;
    }
    p->lastSeq = seq;
  }


  // 4. Decode base64 fields
  String ivB64     = doc["iv"].as<String>();
  String cipherB64 = doc["cipher"].as<String>();
  String macB64    = doc["mac"].as<String>();

  // Buffers for decoded data
  uint8_t *ivBuf      = nullptr;
  size_t   ivLen      = 0;
  uint8_t *cipherBuf  = nullptr;
  size_t   cipherLen  = 0;
  uint8_t *macBuf     = nullptr;
  size_t   macLen     = 0;
  uint8_t *headerBuf  = nullptr;
  size_t   headerLen  = 0;
  uint8_t *plainBuf   = nullptr;
  size_t   plainLen   = 0;

  bool ok = true;

  // 5. Decode base64
  if (!base64Decode(ivB64, &ivBuf, &ivLen) || ivLen != 16) {
    Serial.println("IV decode failed");
    ok = false;
  }

  if (ok && (!base64Decode(cipherB64, &cipherBuf, &cipherLen))) {
    Serial.println("Cipher decode failed");
    ok = false;
  }

  if (ok && (!base64Decode(macB64, &macBuf, &macLen) || macLen != 32)) {
    Serial.println("MAC decode failed");
    ok = false;
  }

  // 6. Rebuild header and verify HMAC
  if (ok) {
    buildHeader(deviceId, roomId, typeStr, seq, ivBuf, &headerBuf, &headerLen);
    uint8_t expectedMac[32];
    if (!computeHmac(headerBuf, headerLen, cipherBuf, cipherLen, expectedMac)) {
      Serial.println("HMAC compute failed");
      ok = false;
    } else if (memcmp(expectedMac, macBuf, 32) != 0) {
      Serial.println("MAC mismatch, dropping");
      ok = false;
    }
  }

  // 7. Decrypt
  if (ok) {
    if (!aesCbcDecrypt(cipherBuf, cipherLen, ivBuf, &plainBuf, &plainLen)) {
      Serial.println("Decrypt failed");
      ok = false;
    }
  }

  // 8. Parse inner JSON and process
  if (ok) {
    StaticJsonDocument<256> inner;
    DeserializationError err2 = deserializeJson(inner, plainBuf, plainLen);
    if (err2) {
      Serial.println("Inner JSON parse failed");
      ok = false;
    } else {
      processPlaintextPayload(typeStr, inner, deviceId);
    }
  }

  // 9. Cleanup
  if (plainBuf)   free(plainBuf);
  if (headerBuf)  free(headerBuf);
  if (ivBuf)      free(ivBuf);
  if (cipherBuf)  free(cipherBuf);
  if (macBuf)     free(macBuf);
}


// =======================
// MQTT connect and LWT
// =======================
void connectMQTT() {
  while (!mqttClient.connected()) {
    String clientId = "ESP32-" + String(DEVICE_ID);
    Serial.print("Connecting to MQTT...");
// 1. Build the LWT payload (encrypted JSON envelope)
    // This string MUST be built right here before the connect call.
    String lwtMsg = buildPresenceOfflineLWT(); 
    if (lwtMsg.length() == 0) {
      Serial.println(" (LWT build failed, retrying)");
      delay(1000);
      continue;
    }
    
    // 2. Use the PubSubClient.connect overload that accepts LWT parameters.
    // This is the correct way to set LWT in this library.
    bool ok = mqttClient.connect(
      clientId.c_str(),
      nullptr, nullptr,               // no username/password
      topicPresence.c_str(),          // will topic
      1,                              // will QoS
      true,                           // will retained
      lwtMsg.c_str()                  // will message (encrypted envelope)
    );

    if (ok) {
      Serial.println("connected");
      mqttClient.subscribe(topicRoom.c_str());
      mqttClient.subscribe(topicPresence.c_str());

      // Normal PRESENCE ONLINE message (using your existing function)
      sendPresenceOnline();
      /* Check this.
      if (!sentOnlineThisSession) {
        sendPresenceOnline();
        sentOnlineThisSession = true;
      }

      */
    } else {
      Serial.print(" failed, rc=");
      Serial.println(mqttClient.state());
      delay(1000);
    }
  }
}


// Build a PRESENCE OFFLINE message as encrypted envelope for LWT
// Build a PRESENCE OFFLINE message as an encrypted envelope for LWT.
// Uses seq = 0 reserved for LWT.
String buildPresenceOfflineLWT() {
  const uint32_t lwtSeq = 0;

  // 1) IV
  uint8_t iv[16];
  generateRandomIV(iv);

  // 2) Inner JSON payload
  String innerJson = "{\"status\":\"OFFLINE\"}";
  const uint8_t *plainBytes = (const uint8_t*)innerJson.c_str();
  size_t plainLen = innerJson.length();

  // 3) Encrypt inner JSON with AES-CBC
  uint8_t *cipherBuf = nullptr;
  size_t cipherLen = 0;
  if (!aesCbcEncrypt(plainBytes, plainLen, iv, &cipherBuf, &cipherLen)) {
    Serial.println("LWT encryption failed");
    return String("");
  }

  // 4) Build header and compute HMAC over header || cipher
  uint8_t *headerBuf = nullptr;
  size_t   headerLen = 0;
  buildHeader(DEVICE_ID, ROOM_ID, "PRESENCE", lwtSeq, iv, &headerBuf, &headerLen);

  uint8_t mac[32];
  if (!computeHmac(headerBuf, headerLen, cipherBuf, cipherLen, mac)) {
    Serial.println("LWT HMAC failed");
    free(headerBuf);
    free(cipherBuf);
    return String("");
  }

  // 5) Base64 encode iv, cipher, mac
  String ivB64, cipherB64, macB64;
  if (!base64Encode(iv, 16, ivB64) ||
      !base64Encode(cipherBuf, cipherLen, cipherB64) ||
      !base64Encode(mac, 32, macB64)) {
    Serial.println("LWT base64 failed");
    free(headerBuf);
    free(cipherBuf);
    return String("");
  }

  free(headerBuf);
  free(cipherBuf);

  // 6) Build full envelope JSON (same format as all other messages)
  String msg = "{";
  msg += "\"device_id\":\""; msg += DEVICE_ID; msg += "\",";
  msg += "\"room_id\":\"";   msg += ROOM_ID;   msg += "\",";
  msg += "\"type\":\"PRESENCE\",";
  msg += "\"seq\":";         msg += String(lwtSeq); msg += ",";
  msg += "\"iv\":\"";        msg += ivB64;     msg += "\",";
  msg += "\"cipher\":\"";    msg += cipherB64; msg += "\",";
  msg += "\"mac\":\"";       msg += macB64;    msg += "\"";
  msg += "}";

  return msg;
}


// =======================
// Setup / loop
// =======================

void setup() {
  Serial.begin(115200);
  delay(1000);

  pinMode(LED_WHITE_PIN, OUTPUT);
  pinMode(LED_RED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  dht_sensor.begin();

  topicRoom     = String("factory/") + ROOM_ID;
  topicPresence = topicRoom + "/presence";
  bootMs = millis();
  delay(50);
  Serial.print("Button at boot: ");
  Serial.println(digitalRead(BUTTON_PIN) == LOW ? "PRESSED/LOW" : "RELEASED/HIGH");

  lastButton = digitalRead(BUTTON_PIN);
  buttonArmed = false;


  connectWiFi();

  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  mqttClient.setCallback(mqttCallback);

  connectMQTT();
}

void loop() {
  /*if (!mqttClient.connected()) {
    connectMQTT();
  }
  mqttClient.loop();*/
  if (!mqttClient.connected()) {
    unsigned long now = millis();
    if (now - lastReconnectAttemptMs >= RECONNECT_BACKOFF_MS) {
      lastReconnectAttemptMs = now;
      sentOnlineThisSession = false;   // new session
      connectMQTT();
    }
    delay(50);
    return;
  }

  mqttClient.loop();

  // Read local sensor and send every 5 seconds
  unsigned long now = millis();
  if (now - lastSensorSend > 5000) {
    lastSensorSend = now;

    float t = dht_sensor.readTemperature();  // Celsius
    float h = dht_sensor.readHumidity();

    if (!isnan(t) && !isnan(h)) {
      localTemp = t;
      localHum  = h;

      StaticJsonDocument<64> inner;
      inner["temp"]     = t;
      inner["humidity"] = h;

      String innerJson;
      serializeJson(inner, innerJson);
      sendSecureMessage("SENSOR", innerJson, topicRoom.c_str(), false);
    } else {
      Serial.println("DHT read failed");
    }
  }

  // Arm the button after boot settles (prevents boot false-trigger)
  if (!buttonArmed && millis() - bootMs > 2000) {   // 2s grace period
    buttonArmed = true;
  }

  // Emergency button (active low)
  bool btn = digitalRead(BUTTON_PIN);
  if (buttonArmed && lastButton == HIGH && btn == LOW) {
    // Debounce
    delay(30);
    if (digitalRead(BUTTON_PIN) == LOW) {
      StaticJsonDocument<32> inner;
      inner["status"] = "EMERGENCY";
      String innerJson;
      serializeJson(inner, innerJson);
      sendSecureMessage("EMERGENCY", innerJson, topicRoom.c_str(), true);
      digitalWrite(LED_RED_PIN, HIGH);
    }
  }
  lastButton = btn;


  // Update white LED based on current state
  updateWhiteLed();
}
