# Alen DPI Applet

A powerful Deep Packet Inspection (DPI) and Network Traffic Analysis dashboard. This application provides real-time monitoring, offline PCAP file analysis, and threat intelligence capabilities with a modern, high-performance UI.

## Features

- **Live Traffic Stream**: Monitor network packets in real-time via WebSocket integration.
- **Dashboard Overview**: Visualizes network I/O, live throughput, and protocol distribution using interactive charts.
- **Offline PCAP Analysis**: Upload and analyze Wireshark `.pcap` and `.pcapng` files.
- **Threat Intelligence**: Identifies malicious signatures and tracks active threats with a dedicated threat log.
- **Advanced Filtering**: Use the Query Builder to filter packets by source, destination, protocol, and port.
- **Data Export**: Export session metadata and filtered packet lists directly to JSON or CSV formats.
- **Multi-language Support**: Built-in support for English and German.

## Tech Stack

- **Framework:** Next.js 15 (App Router, React)
- **Styling:** Tailwind CSS (v4)
- **Icons:** Lucide React
- **Charts:** Recharts
- **Animations:** Framer Motion

## Getting Started

### Prerequisites

Ensure you have Node.js and npm installed.

### Installation

Install the required dependencies:

```bash
npm install
```

### Development

To run the application in development mode:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

### Python DPI Agent (Live Capture)

To feed live data to the dashboard, a Python agent is included (`python_agent.py`). It acts as a WebSocket server on port `8080` that the dashboard connects to.

1. Ensure you have Python 3 installed.
2. Install the required dependencies:
   ```bash
   pip install websockets scapy
   ```
3. (Windows Users Only) Install Npcap from https://npcap.com/ to enable live packet capture.
4. Run the agent (requires Administrator/root privileges):
   ```bash
   python python_agent.py
   ```
5. Open the dashboard and click "Connect" on the Live Traffic Stream section.

### Production / Publication

This application is ready for production environments. To build and start the optimized production version:

```bash
npm run build
npm run start
```

You can deploy this application using standard Next.js deployment methods, such as deploying to Vercel, Google Cloud Run, or any Docker-compatible hosting environment.
