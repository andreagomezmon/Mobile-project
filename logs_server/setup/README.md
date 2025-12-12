# Secure Cookie Factory

## Project Overview
The Secure Cookie Factory project is designed to manage and log events from various devices in a secure manner. It utilizes MQTT for message handling, cryptographic techniques for data integrity and confidentiality, and SQLite for data storage.

## File Structure
```
secure-cookie-factory
├── src
│   └── log_server.py          # Main logic for the log server
├── scripts
│   └── init_db.py            # Script to initialize the SQLite database
├── db
│   └── init.sql              # SQL commands for creating tables and inserting data
├── requirements.txt           # Project dependencies
└── README.md                  # Project documentation
```

## Setup Instructions

1. **Clone the Repository**
   Clone this repository to your local machine using:
   ```
   git clone <repository-url>
   ```

2. **Install Dependencies**
   Navigate to the project directory and install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. **Initialize the Database**
   Run the `init_db.py` script to set up the SQLite database:
   ```
   python scripts/init_db.py
   ```

4. **Run the Log Server**
   Start the log server by executing:
   ```
   python src/log_server.py
   ```

## Usage
- The log server listens for MQTT messages from devices, verifies their integrity, and logs the events into a CSV file.
- Ensure that the devices are configured to send messages to the correct MQTT broker.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.