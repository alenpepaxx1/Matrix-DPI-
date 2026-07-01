#!/usr/bin/env python3
"""
Alen DPI Applet - Python Agent Example
This script connects to the Alen DPI dashboard via WebSockets.
It strictly performs live packet capture using `scapy`.

Dependencies:
    pip install websockets
    pip install scapy

Usage:
    python python_agent.py
"""

import asyncio
import json
import uuid
import time
from datetime import datetime

try:
    import websockets
except ImportError:
    print("Error: 'websockets' library is required.")
    print("Install it using: pip install websockets")
    exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("Error: 'scapy' library is required for live capture.")
    print("Install it using: pip install scapy")
    exit(1)
except OSError:
    print("Error: Insufficient permissions for live capture.")
    print("Please run this script with Administrator/Root privileges.")
    exit(1)

HOST = "127.0.0.1"
PORT = 8080

# Keep track of active WebSocket connections
connected_clients = set()
MAIN_LOOP = None

def process_live_packet(packet):
    """Extracts DPI data from a real Scapy packet."""
    try:
        is_malicious = False
        protocol = "Unknown"
        src = "0.0.0.0"
        dst = "0.0.0.0"
        info = "Packet captured"
        
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            if TCP in packet:
                protocol = "TCP"
                src = f"{src}:{packet[TCP].sport}"
                dst = f"{dst}:{packet[TCP].dport}"
                info = f"TCP Seq: {packet[TCP].seq} Ack: {packet[TCP].ack}"
                
                # Basic threat detection logic (example)
                if packet[TCP].dport in [4444, 1337, 6667]:
                    is_malicious = True
                    info = f"SUSPICIOUS PORT {packet[TCP].dport} DETECTED"
                    
            elif UDP in packet:
                protocol = "UDP"
                src = f"{src}:{packet[UDP].sport}"
                dst = f"{dst}:{packet[UDP].dport}"
                info = f"UDP Len: {packet[UDP].len}"
            elif packet.haslayer("ICMP"):
                protocol = "ICMP"
                info = "ICMP Echo/Reply"
            else:
                protocol = f"IP/{packet[IP].proto}"
                info = packet.summary()
        else:
            protocol = packet.name if hasattr(packet, 'name') else "Unknown Layer 2"
            if packet.haslayer('Ether'):
                src = packet['Ether'].src
                dst = packet['Ether'].dst
            elif hasattr(packet, 'src') and hasattr(packet, 'dst'):
                src = packet.src
                dst = packet.dst
            else:
                src = "N/A"
                dst = "N/A"
            info = packet.summary()

        # Convert hex representation
        hex_data = bytes(packet)[:16].hex(' ') if hasattr(bytes, 'hex') else "N/A"

        return {
            "id": str(uuid.uuid4()),
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": src,
            "destination": dst,
            "protocol": protocol,
            "length": len(packet),
            "info": info,
            "isMalicious": is_malicious,
            "hex": hex_data,
            "decoded": [
                packet.summary()
            ],
            "note": "Live capture" if not is_malicious else "Suspicious Activity"
        }
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

async def handler(websocket):
    """Handles new WebSocket connections from the React dashboard."""
    connected_clients.add(websocket)
    print(f"[+] Dashboard connected. Active clients: {len(connected_clients)}")
    try:
        # Keep connection open
        async for message in websocket:
            # Handle incoming commands from dashboard if needed
            print(f"Received from client: {message}")
    except websockets.exceptions.ConnectionClosed:
        print("[-] Dashboard disconnected.")
    finally:
        connected_clients.remove(websocket)

def live_capture_callback(packet):
    """Callback function for scapy sniff()."""
    if not connected_clients:
        return
        
    packet_data = process_live_packet(packet)
    if packet_data:
        message = json.dumps({
            "type": "packet",
            "packet": packet_data
        })
        
        throughput = json.dumps({
            "type": "throughput",
            "value": len(packet) * 100  # Scaling for visualization
        })
        
        # Schedule the send coroutine in the main event loop
        if MAIN_LOOP and MAIN_LOOP.is_running():
            for ws in list(connected_clients):
                asyncio.run_coroutine_threadsafe(ws.send(message), MAIN_LOOP)
                asyncio.run_coroutine_threadsafe(ws.send(throughput), MAIN_LOOP)

async def start_live_capture():
    """Starts the scapy packet sniffer in a separate thread."""
    print("[*] Starting Live Packet Capture...")
    print("[!] Ensure you are running this script with Administrator/Root privileges.")
    print("[!] On Windows, you MUST install Npcap (https://npcap.com/) for live capture to work.")
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(
            None, 
            lambda: sniff(prn=live_capture_callback, store=False)
        )
    except Exception as e:
        print(f"\n[!] Live capture failed: {e}")
        print("[!] This is usually caused by missing Npcap/WinPcap on Windows.")
        print("[!] Please install Npcap, ensure you have sufficient permissions, and try again.")
        exit(1)

async def main():
    global MAIN_LOOP
    MAIN_LOOP = asyncio.get_running_loop()
    print(f"[*] Starting WebSocket server on ws://{HOST}:{PORT}")
    
    # Modern websockets.serve supports both standard handler signatures
    async with websockets.serve(handler, HOST, PORT):
        await start_live_capture()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
