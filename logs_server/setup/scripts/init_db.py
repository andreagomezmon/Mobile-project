import sqlite3
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "devices.db"

def init_db():
    # Connect to the SQLite database (it will be created if it doesn't exist)
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()

    # Create room_keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS room_keys (
            room_id TEXT PRIMARY KEY,
            enc_hex TEXT NOT NULL,
            mac_hex TEXT NOT NULL
        )
    ''')

    # Create expected_devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS expected_devices (
            room_id TEXT,
            device_id TEXT,
            PRIMARY KEY (room_id, device_id)
        )
    ''')

    # Insert initial data into room_keys
    cursor.execute('''
        INSERT OR REPLACE INTO room_keys (room_id, enc_hex, mac_hex) VALUES
        ('Room1', '01010101010101010101010101010101', '0202020202020202020202020202020202020202020202020202020202020202'),
        ('Room2', '01010101010101010101010101010101', '0202020202020202020202020202020202020202020202020202020202020202')
    ''')

    # Insert initial data into expected_devices
    cursor.execute('''
        INSERT OR REPLACE INTO expected_devices (room_id, device_id) VALUES
        ('Room1', 'D001'),
        ('Room1', 'D002'),
        ('Room2', 'D001'),
        ('Room2', 'D002')
    ''')

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()