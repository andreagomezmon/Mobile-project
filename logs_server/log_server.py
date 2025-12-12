#!/usr/bin/env python3
import json
import os
import time
import logging
import csv
import base64
from pathlib import Path
from typing import Dict, Any

import paho.mqtt.client as mqtt
from jsonschema import validate, ValidationError

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Util.Padding import unpad

import sqlite3

# ===========================
# Configuration
# ===========================

MQTT_HOST = "127.0.0.1" #192.168.1.20"    # change to your laptop IP if needed
MQTT_PORT = 1883
MQTT_CLIENT_ID = "CookieLogServer"

# Directory where JSON schemas live
BASE_DIR = Path(__file__).resolve().parent
SCHEMA_DIR = BASE_DIR.parent / "Json"

DB_PATH = BASE_DIR.parent / "devices.db"


"""
# Per-room keys (must match ESP32 code)
# Here only one room is defined, extend as needed
ROOM_KEYS = {
    "Room1": {
        "enc": bytes([
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        ]),
        "mac": bytes([
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
        ])
    }
}

# Which device ids we expect in each room
EXPECTED_DEVICES = {
    "Room1": {"D001", "D002"}
}"""

LOG_FILE = "logs.csv"

# Simple thresholds for anomaly alerts
MAX_INVALID_MAC_BEFORE_ALERT = 10


# ===========================
# Logging setup
# ===========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ===========================
# Load JSON Schemas
# ===========================

def load_schema(name: str) -> Dict[str, Any]:
    path = SCHEMA_DIR / name
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

schema_envelope = load_schema("envelope.schema.json")
schema_sensor = load_schema("payload-sensor.schema.json")
schema_emergency = load_schema("payload-emergency.schema.json")
schema_presence = load_schema("payload-presence.schema.json")
schema_config = load_schema("payload-config.schema.json")


# ===========================
# State for monitoring
# ===========================

invalid_mac_count = 0
last_seq_per_device: Dict[str, int] = {}
presence_status: Dict[str, str] = {}  # device_id -> "ONLINE" or "OFFLINE"


# ===========================
# Crypto helpers
# ===========================

def build_header_bytes(device_id: str, room_id: str,
                       msg_type: str, seq: int,
                       iv: bytes) -> bytes:
    """
    Must match the ESP32 buildHeader logic:
    header = device_id || room_id || type || seq_string || iv_bytes
    """
    s = device_id + room_id + msg_type + str(seq)
    return s.encode("utf-8") + iv

def verify_and_decrypt(room_id: str, envelope: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify HMAC and decrypt AES-CBC. Returns inner JSON dict.
    Raises ValueError on MAC / padding / JSON / key errors.
    Replay is only logged, not treated as a hard failure.
    """
    global last_seq_per_device

    room_keys = get_room_keys(room_id)
    if room_keys is None:
        raise ValueError(f"No keys for room {room_id} in DB")

    key_enc = room_keys["enc"]
    key_mac = room_keys["mac"]

    device_id = envelope["device_id"]
    msg_type = envelope["type"]
    seq = envelope["seq"]

    iv_b64 = envelope["iv"]
    cipher_b64 = envelope["cipher"]
    mac_b64 = envelope["mac"]

    try:
        iv = base64.b64decode(iv_b64)
        cipher = base64.b64decode(cipher_b64)
        mac = base64.b64decode(mac_b64)
    except Exception as e:
        raise ValueError(f"Base64 decode error: {e}")

    if len(iv) != 16:
        raise ValueError("IV length is not 16 bytes")
    if len(mac) != 32:
        raise ValueError("MAC length is not 32 bytes")

    # Build header and compute expected HMAC
    header = build_header_bytes(device_id, room_id, msg_type, seq, iv)

    h = HMAC.new(key_mac, digestmod=SHA256)
    h.update(header)
    h.update(cipher)
    try:
        h.verify(mac)
    except ValueError:
        raise ValueError("MAC verification failed")

    # --- Replay detection: enforce monotonic increase for each (room, device) ---
    # LWT PRESENCE with seq == 0 is special-cased and always allowed
    if not (msg_type == "PRESENCE" and seq == 0):
        dev_key = f"{room_id}:{device_id}"
        last_seq = last_seq_per_device.get(dev_key)
        if last_seq is not None and seq <= last_seq:
            logging.warning(
                "Replay or out-of-order sequence detected for %s in %s: seq=%d last_seq=%d",
                device_id, room_id, seq, last_seq,
            )
            # Treat as a hard failure so the caller drops the message
            raise ValueError("Replay or out-of-order sequence number")
        # Accept and update last_seq
        last_seq_per_device[dev_key] = seq
    # ------------------------------------------------

    # Decrypt with AES-CBC
    cipher_obj = AES.new(key_enc, AES.MODE_CBC, iv=iv)
    plaintext_padded = cipher_obj.decrypt(cipher)
    try:
        plaintext = unpad(plaintext_padded, AES.block_size)
    except ValueError:
        raise ValueError("PKCS7 unpad failed")

    try:
        inner = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Inner JSON parse error: {e}")

    return inner


# ===========================
# JSON validation helpers
# ===========================

def validate_envelope(envelope: Dict[str, Any]) -> None:
    validate(instance=envelope, schema=schema_envelope)


def validate_inner_payload(msg_type: str, payload: Dict[str, Any]) -> None:
    if msg_type == "SENSOR":
        validate(instance=payload, schema=schema_sensor)
    elif msg_type == "EMERGENCY":
        validate(instance=payload, schema=schema_emergency)
    elif msg_type == "PRESENCE":
        validate(instance=payload, schema=schema_presence)
    elif msg_type == "CONFIG":
        validate(instance=payload, schema=schema_config)
    else:
        raise ValidationError(f"Unknown type {msg_type}")


# ===========================
# CSV logging
# ===========================

def init_log_file():
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp",
                "room_id",
                "device_id",
                "type",
                "seq",
                "payload_json"
            ])

def log_event(room_id: str, device_id: str,
              msg_type: str, seq: int,
              payload: Dict[str, Any]):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            ts,
            room_id,
            device_id,
            msg_type,
            seq,
            json.dumps(payload, separators=(",", ":"))
        ])


# ===========================
# Alerting helper
# ===========================

def alert_admin(message: str):
    # For the project: print to console.
    # In a real system this could send email, Slack, etc.
    logging.warning(f"[ALERT] {message}")


# ===========================
# MQTT callbacks
# ===========================

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logging.info("Connected to MQTT broker")
        client.subscribe("factory/#")
    else:
        logging.error(f"MQTT connection failed with code {rc}")


def on_message(client, userdata, msg):
    global invalid_mac_count

    topic = msg.topic
    payload_bytes = msg.payload

    # Basic size limit
    if len(payload_bytes) > 4096:
        logging.warning("Dropping oversized MQTT message")
        return

    try:
        envelope = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        logging.warning("Outer JSON parse failed")
        return

    # Validate envelope structure
    try:
        validate_envelope(envelope)
    except ValidationError as e:
        logging.warning(f"Envelope schema validation failed: {e.message}")
        return

    room_id = envelope["room_id"]
    device_id = envelope["device_id"]
    msg_type = envelope["type"]
    seq = envelope["seq"]

    # Check room has keys in DB (otherwise drop early)
    if get_room_keys(room_id) is None:
        logging.warning(f"Unknown room_id {room_id} (no keys in DB), dropping")
        return

    # Check if device is expected (DB-based or always true)
    if not is_expected_device(room_id, device_id):
        alert_admin(f"Unknown device_id {device_id} in room {room_id}")

    # Verify MAC and decrypt
    try:
        inner = verify_and_decrypt(room_id, envelope)
    except ValueError as e:
        # Could be MAC failure, replay, padding error, etc.
        msg_txt = str(e)
        logging.warning(f"Crypto failure from {device_id} in {room_id}: {msg_txt}")
        if "MAC" in msg_txt:
            invalid_mac_count += 1
            if invalid_mac_count >= MAX_INVALID_MAC_BEFORE_ALERT:
                alert_admin("Too many invalid MACs observed, possible active attack")
                invalid_mac_count = 0
        return

    # Validate inner payload
    try:
        validate_inner_payload(msg_type, inner)
    except ValidationError as e:
        logging.warning(f"Inner payload schema validation failed: {e.message}")
        return

    # Update presence status if needed
    if msg_type == "PRESENCE":
        status = inner.get("status")
        presence_status[device_id] = status
        logging.info(f"PRESENCE {status} from {device_id} in {room_id}")
        if status == "OFFLINE":
            alert_admin(f"Device {device_id} in {room_id} went OFFLINE")
    elif msg_type == "EMERGENCY":
        logging.info(f"EMERGENCY from {device_id} in {room_id}: {inner}")
        alert_admin(f"Emergency event from {device_id} in {room_id}")
    elif msg_type == "SENSOR":
        logging.info(f"SENSOR from {device_id} in {room_id}: {inner}")
    elif msg_type == "CONFIG":
        logging.info(f"CONFIG for room {room_id} from {device_id}: {inner}")
        # You could apply configuration server side here if needed

    # Log all valid events
    log_event(room_id, device_id, msg_type, seq, inner)


# ===========================
# Main
# ===========================

def main():
    init_log_file()

    client = mqtt.Client(client_id=MQTT_CLIENT_ID, clean_session=True)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)

    logging.info("Starting MQTT loop, listening on factory/#")
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        logging.info("Stopping log server")

# ===========================
# SQLite helpers
# ===========================
def get_db_connection():
    # You can keep a global connection or open per call.
    # For simplicity here we open per call (SQLite can handle it).
    return sqlite3.connect(DB_PATH)

def get_room_keys(room_id: str):
    """
    Look up AES and HMAC keys for a given room from SQLite.
    Keys are stored as hex strings and converted to bytes here.
    Returns dict {"enc": bytes, "mac": bytes} or None.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT enc_hex, mac_hex FROM room_keys WHERE room_id = ?",
            (room_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        enc_hex, mac_hex = row
        try:
            enc_key = bytes.fromhex(enc_hex)
            mac_key = bytes.fromhex(mac_hex)
        except ValueError as e:
            logging.error(f"Invalid hex keys in DB for room {room_id}: {e}")
            return None
        return {"enc": enc_key, "mac": mac_key}
    finally:
        conn.close()

def is_expected_device(room_id: str, device_id: str) -> bool:
    """
    Check in DB whether device_id is expected in room_id.
    If table not used, you can always return True.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM expected_devices WHERE room_id = ? AND device_id = ?",
            (room_id, device_id)
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


if __name__ == "__main__":
    main()
