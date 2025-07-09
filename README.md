# Anomaly Detection Backend

## Overview
This backend service captures live network traffic, analyzes it for anomalies using a pre-trained machine learning model, and exposes a REST API for controlling the capture and retrieving results. The anomaly detection logic is implemented in Python, while the backend server is built with Node.js and Express.

## Features
- Start and stop live network traffic capture
- Analyze packets for anomalies using a trained model
- Retrieve results and protocol breakdown via API
- Integration between Node.js and Python

## Project Structure
```
Backend/
  |-- index.js                # Main server entry point
  |-- package.json            # Node.js dependencies and scripts
  |-- routes/
  |    |-- anomaly.js         # API endpoints for anomaly detection
  |-- utils/
  |    |-- runPython.js       # Node.js <-> Python integration
  |-- model/
  |    |-- live_sniff.py      # Python script for live packet sniffing and anomaly detection
  |    |-- anomaly_model.pkl  # Trained ML model (binary)
  |    |-- scaler.pkl         # Scaler for feature normalization (binary)
  |    |-- encoder.pkl        # Encoder for protocol features (binary)
  |-- anomaly_results.csv     # Output file with analyzed packet results
```

## Setup Instructions

### Prerequisites
- **Node.js** (v16+ recommended)
- **Python** (v3.7+ recommended)
- Python packages: `pandas`, `joblib`, `scapy`
- The trained model and preprocessing files (`anomaly_model.pkl`, `scaler.pkl`, `encoder.pkl`) must be present in the `model/` directory.

### Install Node.js Dependencies
```bash
npm install
```

### Install Python Dependencies
```bash
pip install pandas joblib scapy
```

## Running the Backend
Start the backend server (runs on port 3000 by default):
```bash
npm start
```

## API Endpoints
All endpoints are prefixed with `/api`.

### POST `/api/start`
Start live network traffic capture and anomaly detection.
- **Response:** `{ started: true }` or `{ running: true }`

### POST `/api/stop`
Stop the live capture process.
- **Response:** `{ stopped: true }` or `{ running: false }`

### GET `/api/results`
Retrieve the results of analyzed packets.
- **Response:**
  - `total_packets`: Total packets analyzed
  - `anomalies`: Number of detected anomalies
  - `normal`: Number of normal packets
  - `protocol_breakdown`: Object with protocol counts
  - `recent`: Array of recent packet data (from `anomaly_results.csv`)
  - `running`: Whether the capture is currently running

#### Example Response
```json
{
  "total_packets": 1000,
  "anomalies": 12,
  "normal": 988,
  "protocol_breakdown": { "TCP": 500, "UDP": 400, "ARP": 100 },
  "recent": [
    {
      "Time": "2025-04-07 20:06:19",
      "Source": "192.168.29.1",
      "Destination": "192.168.29.168",
      "Protocol": "ARP",
      "Length": "42",
      "Source Port": "0",
      "Destination Port": "0",
      "bad_packet": "0"
    },
    // ...
  ],
  "running": false
}
```

## Output Format
The results are stored in `anomaly_results.csv` with the following columns:
- `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Source Port`, `Destination Port`, `bad_packet`
  - `bad_packet` is `1` for anomalies, `0` for normal packets.

## Notes
- The backend relies on the Python script for live packet capture and anomaly detection. Ensure Python and required packages are installed and accessible.
- The `model/` directory must contain the trained model and preprocessing files.
- The server uses `nodemon` for development; you can use `node index.js` for production.

## License
ISC 