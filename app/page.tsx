/**
 * Copyright (c) 2026 Alen Pepa
 * All rights reserved.
 */
'use client';

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { motion } from 'framer-motion';
import { AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, ShieldAlert, Wifi, Server, FileSearch, Settings, Download, Upload, Play, Square, Filter, Terminal, Database, SquareActivity, AlertTriangle, Code, LayoutDashboard, Search, Globe, Edit2, Save, X, FileText } from 'lucide-react';

interface Packet {
  id: string;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  isMalicious: boolean;
  hex: string;
  decoded: string[];
  note?: string;
}

export type FilterCondition = {
  id: string;
  field: 'source' | 'destination' | 'protocol' | 'length' | 'info';
  operator: 'contains' | 'equals' | 'starts_with' | 'ends_with' | 'greater_than' | 'less_than';
  value: string;
};

const pythonCodeString = `#!/usr/bin/env python3
"""
Alen DPI Applet - Python Agent Example
This script connects to the Alen DPI dashboard via WebSockets.
It strictly performs live packet capture using \`scapy\`.

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
            # Skip non-IP packets to reduce noise
            return None

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
`;

const parseHexDumpToAscii = (hexDump: string) => {
  if (!hexDump || hexDump === "No payload") return "No payload";
  let result = "";
  hexDump.split('\n').forEach(line => {
    // Scapy hexdump output typically looks like:
    // 0000  45 00 00 28 00 01 00 00  40 06 7C CD 7F 00 00 01   E..(...@.|......
    // This splits by whitespace.
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 2) return;
    
    // The first token is the offset (e.g. 0000). The next up to 16 tokens are hex bytes.
    const hexPairs = tokens.slice(1).filter(t => /^[0-9a-fA-F]{2}$/.test(t));
    
    result += hexPairs.map(hex => {
      const code = parseInt(hex, 16);
      if (code === 10 || code === 13) return String.fromCharCode(code);
      return (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
    }).join('');
  });
  return result;
};

export default function DPIApp() {
  const [lang, setLang] = useState<'en' | 'de'>('en');
  const [packets, setPackets] = useState<Packet[]>([]);
  const [captured, setCaptured] = useState(0);
  const [malicious, setMalicious] = useState(0);
  const [throughputData, setThroughputData] = useState<{time: string, value: number}[]>(() => 
    Array.from({ length: 20 }).map(() => ({ time: '', value: 0 }))
  );
  const [isCapturing, setIsCapturing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connecting' | 'connected'>('disconnected');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'live' | 'topology' | 'analyzer' | 'threats' | 'agent'>('live');
  const [wsEndpoint, setWsEndpoint] = useState('ws://127.0.0.1:8080');
  const [selectedPackets, setSelectedPackets] = useState<Packet[]>([]);
  const [isCompareMode, setIsCompareMode] = useState(false);
  const [payloadViewMode, setPayloadViewMode] = useState<'hex' | 'ascii'>('hex');
  const [wsError, setWsError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterConditions, setFilterConditions] = useState<FilterCondition[]>([]);
  const [isQueryBuilderOpen, setIsQueryBuilderOpen] = useState(false);
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [editingNoteText, setEditingNoteText] = useState('');
  
  const wsRef = useRef<WebSocket | null>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const translations = {
    en: {
      appTitle: "MATRIX DPI",
      appSubtitle: "Advanced Deep Packet Inspection Engine",
      copyright: "© 2026 Alen Pepa. All rights reserved.",
      dashboard: "Dashboard",
      liveCapture: "Live Capture",
      topology: "Network Topology",
      pcapAnalyzer: "PCAP Analyzer",
      threatIntel: "Threat Intel",
      agentSetup: "Agent Setup",
      agentSetupSubtitle: "Deploy the local capture agent to begin streaming packets to this dashboard.",
      agentSetupInstTitle: "Installation & Setup Instructions",
      agentSetupStep1: "1. Ensure you have Python 3 installed.",
      agentSetupStep2: "2. Install the required dependencies: pip install websockets scapy",
      agentSetupStep3: "3. (Windows Users Only) Install Npcap from https://npcap.com/ to enable live packet capture.",
      agentSetupStep4: "4. Run the agent (requires Administrator/root privileges): python python_agent.py",
      liveThroughput: "Live Throughput",
      agentConnected: "AGENT CONNECTED",
      agentConnecting: "CONNECTING...",
      agentDisconnected: "AGENT DISCONNECTED",
      dashboardOverview: "Dashboard Overview",
      exportData: "Export Data",
      downloadJson: "Download JSON",
      downloadCsv: "Download CSV",
      networkIO: "Network I/O",
      protocolDistribution: "Protocol Distribution",
      topSources: "Top Sources (Bytes)",
      liveTrafficStream: "Live Traffic Stream",
      startCapture: "Start Capture",
      stopCapture: "Stop Capture",
      filterPackets: "Filter Packets...",
      clear: "Clear",
      packetDetails: "Packet Details",
      hexDump: "Hex Dump",
      asciiView: "ASCII View",
      decodedPayload: "Decoded Payload",
      noPacketSelected: "No packet selected",
      selectPacketDesc: "Select a packet from the stream to view its details.",
      offlinePcapAnalysis: "Offline PCAP Analysis",
      uploadPcapDesc: "Upload a .pcap or .pcapng file generated by Wireshark.",
      selectPcapFile: "Select PCAP File",
      activeThreats: "Active Threats Detected",
      threatLog: "Threat Log",
      threatSignatures: "Threat Signatures",
      agentStatus: "Agent Status",
      idle: "IDLE",
      syncing: "SYNCING",
      queueSize: "Queue Size",
      localAgentConnection: "Local Agent Connection",
      connectToLocalDPI: "Connect to your local DPI agent (e.g., matrix-agent) running on your machine.",
      connect: "Connect",
      disconnect: "Disconnect",
      payloadData: "Payload Data",
      compareMode: "Compare Mode",
      selectSecondPacket: "Select Second Packet",
      selectSecondPacketDesc: "Click another packet in the stream to compare.",
      queryBuilder: "Query Builder",
      addCondition: "Add Condition",
      applyFilters: "Apply Filters",
      clearFilters: "Clear Filters",
      field: "Field",
      operator: "Operator",
      value: "Value",
      source: "Source",
      destination: "Destination",
      protocol: "Protocol",
      length: "Length",
      info: "Info",
      contains: "Contains",
      equals: "Equals",
      starts_with: "Starts With",
      ends_with: "Ends With",
      greater_than: "Greater Than",
      less_than: "Less Than",
      addNote: "Add Note",
      editNote: "Edit Note",
      saveNote: "Save",
      cancel: "Cancel",
      notePlaceholder: "Add a custom note to this packet..."
    },
    de: {
      appTitle: "MATRIX DPI",
      appSubtitle: "Erweiterte Deep Packet Inspection Engine",
      copyright: "© 2026 Alen Pepa. Alle Rechte vorbehalten.",
      dashboard: "Dashboard",
      liveCapture: "Live-Erfassung",
      topology: "Netzwerktopologie",
      pcapAnalyzer: "PCAP-Analysator",
      threatIntel: "Bedrohungsdaten",
      agentSetup: "Agenten-Setup",
      agentSetupSubtitle: "Stellen Sie den lokalen Erfassungsagenten bereit, um Pakete an dieses Dashboard zu streamen.",
      agentSetupInstTitle: "Installations- und Einrichtungsanweisungen",
      agentSetupStep1: "1. Stellen Sie sicher, dass Python 3 installiert ist.",
      agentSetupStep2: "2. Installieren Sie die erforderlichen Abhängigkeiten: pip install websockets scapy",
      agentSetupStep3: "3. (Nur für Windows-Benutzer) Installieren Sie Npcap von https://npcap.com/, um die Live-Paketerfassung zu aktivieren.",
      agentSetupStep4: "4. Führen Sie den Agenten aus (erfordert Administrator-/Root-Rechte): python python_agent.py",
      liveThroughput: "Live-Durchsatz",
      agentConnected: "AGENT VERBUNDEN",
      agentConnecting: "VERBINDET...",
      agentDisconnected: "AGENT GETRENNT",
      dashboardOverview: "Dashboard-Übersicht",
      exportData: "Daten exportieren",
      downloadJson: "JSON Herunterladen",
      downloadCsv: "CSV Herunterladen",
      networkIO: "Netzwerk I/O",
      protocolDistribution: "Protokollverteilung",
      topSources: "Top-Quellen (Bytes)",
      liveTrafficStream: "Live-Datenverkehr",
      startCapture: "Erfassung starten",
      stopCapture: "Erfassung stoppen",
      filterPackets: "Pakete filtern...",
      clear: "Löschen",
      packetDetails: "Paketdetails",
      hexDump: "Hex-Dump",
      asciiView: "ASCII-Ansicht",
      decodedPayload: "Dekodierte Nutzlast",
      noPacketSelected: "Kein Paket ausgewählt",
      selectPacketDesc: "Wählen Sie ein Paket aus dem Stream aus, um seine Details anzuzeigen.",
      offlinePcapAnalysis: "Offline-PCAP-Analyse",
      uploadPcapDesc: "Laden Sie eine von Wireshark erstellte .pcap- oder .pcapng-Datei hoch.",
      selectPcapFile: "PCAP-Datei auswählen",
      activeThreats: "Aktive Bedrohungen erkannt",
      threatLog: "Bedrohungsprotokoll",
      threatSignatures: "Bedrohungssignaturen",
      agentStatus: "Agentenstatus",
      idle: "LEERLAUF",
      syncing: "SYNCHRONISIERT",
      queueSize: "Warteschlangengröße",
      localAgentConnection: "Lokale Agentenverbindung",
      connectToLocalDPI: "Verbinden Sie sich mit Ihrem lokalen DPI-Agenten (z. B. matrix-agent), der auf Ihrem Computer ausgeführt wird.",
      connect: "Verbinden",
      disconnect: "Trennen",
      payloadData: "Nutzdaten",
      compareMode: "Vergleichsmodus",
      selectSecondPacket: "Zweites Paket auswählen",
      selectSecondPacketDesc: "Klicken Sie auf ein anderes Paket im Stream, um es zu vergleichen.",
      queryBuilder: "Abfrage-Builder",
      addCondition: "Bedingung hinzufügen",
      applyFilters: "Filter anwenden",
      clearFilters: "Filter löschen",
      field: "Feld",
      operator: "Operator",
      value: "Wert",
      source: "Quelle",
      destination: "Ziel",
      protocol: "Protokoll",
      length: "Länge",
      info: "Info",
      contains: "Enthält",
      equals: "Gleich",
      starts_with: "Beginnt mit",
      ends_with: "Endet mit",
      greater_than: "Größer als",
      less_than: "Kleiner als",
      addNote: "Notiz hinzufügen",
      editNote: "Notiz bearbeiten",
      saveNote: "Speichern",
      cancel: "Abbrechen",
      notePlaceholder: "Fügen Sie diesem Paket eine benutzerdefinierte Notiz hinzu..."
    }
  };
  const t = translations[lang];

  const connectWebSocket = useCallback(() => {
    setConnectionStatus('connecting');
    setWsError(null);

    try {
      const ws = new WebSocket(wsEndpoint);
      
      ws.onopen = () => {
        setConnectionStatus('connected');
        setWsError(null);
        setIsCapturing(true);
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'packet') {
            const newPacket = data.packet as Packet;
            
            setPackets(prev => {
              const updated = [newPacket, ...prev].slice(0, 1500);
              return updated;
            });
            setCaptured(c => c + 1);
            if (newPacket.isMalicious) {
              setMalicious(m => m + 1);
            }
          } else if (data.type === 'throughput') {
             const now = new Date().toLocaleTimeString().split(' ')[0];
             setThroughputData(prev => {
               return [...prev.slice(1), { time: now, value: data.value / 1024 }];
             });
          }
        } catch (e) {
          console.error("Failed to parse websocket message", e);
        }
      };
      
      ws.onclose = () => {
        setConnectionStatus('disconnected');
        setIsCapturing(false);
      };
      
      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
        setConnectionStatus('disconnected');
        setWsError(`Failed to connect to ${wsEndpoint}. Ensure your local agent is running.`);
        setIsCapturing(false);
      };
      
      wsRef.current = ws;
    } catch (err) {
      console.error("Invalid WebSocket URL");
      setWsError('Invalid WebSocket URL format. Try ws://127.0.0.1:8080');
      setConnectionStatus('disconnected');
    }
  }, [wsEndpoint]);

  const disconnectWebSocket = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnectionStatus('disconnected');
    setIsCapturing(false);
  };

  const toggleCapture = () => {
    if (isCapturing) {
      disconnectWebSocket();
    } else {
      connectWebSocket();
    }
  };

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      alert(`PCAP Analysis requested for ${file.name}. This feature requires the local backend processing engine.`);
    }
  };

  const handleUpdateNote = (packetId: string, note: string) => {
    setPackets(prev => prev.map(p => p.id === packetId ? { ...p, note } : p));
    setSelectedPackets(prev => prev.map(p => p.id === packetId ? { ...p, note } : p));
    setEditingNoteId(null);
  };

  const downloadJSON = useCallback(() => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(packets, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "session_metadata.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  }, [packets]);

  const downloadCSV = useCallback(() => {
    if (packets.length === 0) return;
    const header = Object.keys(packets[0]).join(",");
    const csvContent = packets.map(p => {
      return Object.values(p).map(value => {
        if (value === undefined || value === null) return '""';
        if (typeof value === 'string') return `"${value.replace(/"/g, '""')}"`;
        if (Array.isArray(value)) return `"${value.join(' | ').replace(/"/g, '""')}"`;
        return `"${value}"`;
      }).join(",");
    }).join("\n");
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(header + "\n" + csvContent);
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "session_metadata.csv");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  }, [packets]);

  const protocolColors: Record<string, string> = {
    'TCP': '#3b82f6',
    'UDP': '#a855f7',
    'HTTP': '#10b981',
    'HTTPS': '#10b981',
    'DNS': '#eab308',
    'TLSv1.3': '#10b981',
    'QUIC': '#f59e0b',
    'ICMP': '#ef4444',
    'SSHv2': '#6366f1',
    'BGP': '#ec4899'
  };

  const getProtocolColor = (proto: string) => protocolColors[proto] || '#888888';

  const protocolData = useMemo(() => {
    const counts: Record<string, number> = {};
    packets.forEach(p => {
      counts[p.protocol] = (counts[p.protocol] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);
  }, [packets]);

  const sourceData = useMemo(() => {
    const counts: Record<string, number> = {};
    packets.forEach(p => {
      counts[p.source] = (counts[p.source] || 0) + p.length;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);
  }, [packets]);

  const filteredPackets = useMemo(() => {
    let result = packets;
    
    if (searchTerm) {
      const lower = searchTerm.toLowerCase();
      result = result.filter(p => 
        p.protocol.toLowerCase().includes(lower) || 
        p.source.includes(lower) || 
        p.destination.includes(lower) ||
        p.info.toLowerCase().includes(lower)
      );
    }
    
    if (filterConditions.length > 0) {
      result = result.filter(p => {
        return filterConditions.every(cond => {
          if (!cond.value) return true;
          
          let packetValue: string | number = '';
          if (cond.field === 'source') packetValue = p.source;
          else if (cond.field === 'destination') packetValue = p.destination;
          else if (cond.field === 'protocol') packetValue = p.protocol;
          else if (cond.field === 'info') packetValue = p.info;
          else if (cond.field === 'length') packetValue = p.length;
          
          if (cond.field === 'length') {
            const numVal = parseInt(cond.value, 10);
            if (isNaN(numVal)) return true;
            const pLen = packetValue as number;
            
            if (cond.operator === 'equals') return pLen === numVal;
            if (cond.operator === 'greater_than') return pLen > numVal;
            if (cond.operator === 'less_than') return pLen < numVal;
            return true;
          } else {
            const strVal = String(packetValue).toLowerCase();
            const searchVal = cond.value.toLowerCase();
            
            if (cond.operator === 'contains') return strVal.includes(searchVal);
            if (cond.operator === 'equals') return strVal === searchVal;
            if (cond.operator === 'starts_with') return strVal.startsWith(searchVal);
            if (cond.operator === 'ends_with') return strVal.endsWith(searchVal);
            return true;
          }
        });
      });
    }
    
    return result;
  }, [packets, searchTerm, filterConditions]);

  const downloadFilteredCSV = useCallback(() => {
    if (filteredPackets.length === 0) return;
    const header = Object.keys(filteredPackets[0]).join(",");
    const csvContent = filteredPackets.map(p => {
      return Object.values(p).map(value => {
        if (value === undefined || value === null) return '""';
        if (typeof value === 'string') return `"${value.replace(/"/g, '""')}"`;
        if (Array.isArray(value)) return `"${value.join(' | ').replace(/"/g, '""')}"`;
        return `"${value}"`;
      }).join(",");
    }).join("\n");
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(header + "\n" + csvContent);
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "filtered_session_metadata.csv");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  }, [filteredPackets]);

  const uniqueNodes = useMemo(() => {
    const nodesMap = new Map<string, { ip: string, count: number, isMalicious: boolean }>();
    packets.forEach(p => {
      if (!nodesMap.has(p.source)) nodesMap.set(p.source, { ip: p.source, count: 0, isMalicious: false });
      if (!nodesMap.has(p.destination)) nodesMap.set(p.destination, { ip: p.destination, count: 0, isMalicious: false });
      nodesMap.get(p.source)!.count += p.length;
      nodesMap.get(p.destination)!.count += p.length;
      if (p.isMalicious) {
        nodesMap.get(p.source)!.isMalicious = true;
        nodesMap.get(p.destination)!.isMalicious = true;
      }
    });
    return Array.from(nodesMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 12); // Limit to top 12 nodes
  }, [packets]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        if (activeTab === 'live') {
          e.preventDefault();
          searchInputRef.current?.focus();
        }
      }
      
      if (e.key === 'Escape') {
        if (isQueryBuilderOpen) {
          setIsQueryBuilderOpen(false);
        } else if (selectedPackets.length > 0) {
          setSelectedPackets([]);
        }
      }
      
      if (activeTab === 'live' && !isCompareMode && !isQueryBuilderOpen && document.activeElement !== searchInputRef.current) {
        if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
          e.preventDefault();
          
          if (filteredPackets.length === 0) return;
          
          if (selectedPackets.length === 0) {
            setSelectedPackets([filteredPackets[0]]);
            return;
          }
          
          const currentIndex = filteredPackets.findIndex(p => p.id === selectedPackets[0]?.id);
          if (currentIndex === -1) return;
          
          if (e.key === 'ArrowUp' && currentIndex > 0) {
            setSelectedPackets([filteredPackets[currentIndex - 1]]);
          } else if (e.key === 'ArrowDown' && currentIndex < filteredPackets.length - 1) {
            setSelectedPackets([filteredPackets[currentIndex + 1]]);
          }
        }
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeTab, isCompareMode, isQueryBuilderOpen, selectedPackets, filteredPackets]);

  return (
    <div className="flex flex-col h-screen w-full bg-[#020502] text-[#d4d4d4] font-sans overflow-hidden select-none">
      <header className="h-14 border-b border-[#1f1f1f] bg-[#050505] flex items-center justify-between px-6 z-10">
        <div className="flex items-center gap-4">
          <div className="flex items-center justify-center w-8 h-8 rounded bg-[#10b981]/20 border border-[#10b981]/30 text-[#10b981]">
            <SquareActivity size={18} />
          </div>
          <div>
            <h1 className="text-sm font-black text-white tracking-widest uppercase">{t.appTitle}</h1>
            <p className="text-[9px] text-[#888] font-mono tracking-wider">{t.appSubtitle}</p>
          </div>
        </div>
        
        <div className="flex items-center bg-[#111] p-1 rounded-md border border-[#222]">
          <button onClick={() => setActiveTab('dashboard')} className={`px-4 py-1.5 text-xs font-medium uppercase tracking-wider rounded transition-colors flex items-center gap-1.5 ${activeTab === 'dashboard' ? 'bg-[#222] text-white shadow-sm' : 'text-[#666] hover:text-[#999]'}`}><LayoutDashboard size={12}/> {t.dashboard}</button>
          <button onClick={() => setActiveTab('live')} className={`px-4 py-1.5 text-xs font-medium uppercase tracking-wider rounded transition-colors ${activeTab === 'live' ? 'bg-[#222] text-white shadow-sm' : 'text-[#666] hover:text-[#999]'}`}>{t.liveCapture}</button>
          <button onClick={() => setActiveTab('topology')} className={`px-4 py-1.5 text-xs font-medium uppercase tracking-wider rounded transition-colors ${activeTab === 'topology' ? 'bg-[#222] text-white shadow-sm' : 'text-[#666] hover:text-[#999]'}`}>{t.topology}</button>
          <button onClick={() => setActiveTab('analyzer')} className={`px-4 py-1.5 text-xs font-medium uppercase tracking-wider rounded transition-colors ${activeTab === 'analyzer' ? 'bg-[#222] text-white shadow-sm' : 'text-[#666] hover:text-[#999]'}`}>{t.pcapAnalyzer}</button>
          <button onClick={() => setActiveTab('threats')} className={`px-4 py-1.5 text-xs font-medium uppercase tracking-wider rounded transition-colors ${activeTab === 'threats' ? 'bg-[#222] text-white shadow-sm' : 'text-[#666] hover:text-[#999]'}`}>{t.threatIntel}</button>
          <button onClick={() => setActiveTab('agent')} className={`px-4 py-1.5 text-xs font-medium uppercase tracking-wider rounded transition-colors flex items-center gap-1.5 ${activeTab === 'agent' ? 'bg-[#10b981]/20 text-[#10b981] shadow-sm' : 'text-[#666] hover:text-[#999]'}`}><Code size={12}/> {t.agentSetup}</button>
        </div>

        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 bg-[#111] p-1 rounded border border-[#222]">
            <button onClick={() => setLang('en')} className={`px-2 py-1 text-xs rounded transition-colors ${lang === 'en' ? 'bg-[#222] text-white' : 'text-[#666] hover:text-white'}`}>🇬🇧 EN</button>
            <button onClick={() => setLang('de')} className={`px-2 py-1 text-xs rounded transition-colors ${lang === 'de' ? 'bg-[#222] text-white' : 'text-[#666] hover:text-white'}`}>🇩🇪 DE</button>
          </div>
          <div className="flex flex-col items-end">
            <span className="text-[10px] text-[#555] uppercase">{t.liveThroughput}</span>
            <span className="text-sm font-mono text-[#10b981]">{throughputData[throughputData.length - 1]?.value.toFixed(2) || '0.00'} KB/s</span>
          </div>
          <div className="px-3 py-1.5 bg-[#111] border border-[#222] rounded flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${connectionStatus === 'connected' ? 'bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.8)]' : connectionStatus === 'connecting' ? 'bg-yellow-500 animate-bounce' : 'bg-red-500'}`}></div>
            <span className="text-[10px] text-[#888] uppercase tracking-wider">
              {connectionStatus === 'connected' ? t.agentConnected : connectionStatus === 'connecting' ? t.agentConnecting : t.agentDisconnected}
            </span>
          </div>
        </div>
      </header>

      <main className="flex flex-1 overflow-hidden relative">
        {activeTab === 'dashboard' && (
           <div className="flex-1 p-8 bg-[#050505] overflow-y-auto">
             <div className="flex justify-between items-center mb-6">
               <h2 className="text-xl font-bold text-white uppercase tracking-tight">{t.dashboardOverview}</h2>
               <button className="px-4 py-2 bg-[#222] hover:bg-[#333] text-xs font-bold uppercase tracking-wider rounded border border-[#333] transition-colors flex items-center gap-2">
                 <Download size={14}/> {t.exportData}
               </button>
             </div>
             
             <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg p-5 flex flex-col">
                   <h3 className="text-xs font-bold text-[#666] uppercase tracking-wider mb-4 flex items-center justify-between">
                     <span>{t.networkIO} (KB/s)</span>
                     <span className="text-[9px] px-2 py-0.5 bg-[#111] rounded text-[#10b981] font-mono border border-[#222]">Deep Packet Inspection Active</span>
                   </h3>
                   <div className="flex-1 min-h-[256px]">
                      <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={throughputData}>
                        <defs>
                          <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                            <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1f1f1f" vertical={false} />
                        <XAxis dataKey="time" stroke="#444" fontSize={10} tickMargin={10} minTickGap={30} />
                        <YAxis stroke="#444" fontSize={10} tickFormatter={(val) => val.toFixed(0)} width={40} />
                        <Tooltip contentStyle={{ backgroundColor: '#111', borderColor: '#333', fontSize: '12px', fontFamily: 'monospace' }} />
                        <Area type="monotone" dataKey="value" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorValue)" isAnimationActive={false} />
                      </AreaChart>
                      </ResponsiveContainer>
                   </div>
                </div>

                <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg p-5 flex flex-col">
                   <h3 className="text-xs font-bold text-[#666] uppercase tracking-wider mb-4">{t.protocolDistribution}</h3>
                   <div className="flex-1 min-h-[256px] flex items-center justify-center">
                     {protocolData.length > 0 ? (
                       <ResponsiveContainer width="100%" height="100%">
                         <PieChart>
                           <Pie
                             data={protocolData}
                             cx="50%"
                             cy="50%"
                             innerRadius={60}
                             outerRadius={90}
                             paddingAngle={5}
                             dataKey="value"
                             stroke="none"
                             isAnimationActive={false}
                           >
                             {protocolData.map((entry, index) => (
                               <Cell key={`cell-${index}`} fill={getProtocolColor(entry.name)} />
                             ))}
                           </Pie>
                           <Tooltip contentStyle={{ backgroundColor: '#111', borderColor: '#333', fontSize: '12px', fontFamily: 'monospace' }} />
                         </PieChart>
                       </ResponsiveContainer>
                     ) : (
                       <div className="text-[#555] font-mono text-sm">No data</div>
                     )}
                   </div>
                </div>
             </div>

             <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg p-5">
                   <h3 className="text-xs font-bold text-[#666] uppercase tracking-wider mb-4 flex items-center justify-between">
                     {t.topSources} <Server size={14} className="text-[#444]" />
                   </h3>
                   <div className="h-48">
                      {sourceData.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={sourceData} layout="vertical" margin={{ top: 0, right: 0, left: 20, bottom: 0 }}>
                          <XAxis type="number" hide />
                          <YAxis dataKey="name" type="category" stroke="#888" fontSize={10} width={90} axisLine={false} tickLine={false} />
                          <Tooltip cursor={{ fill: '#1f1f1f' }} contentStyle={{ backgroundColor: '#111', borderColor: '#333', fontSize: '12px', fontFamily: 'monospace' }} />
                          <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} isAnimationActive={false} barSize={16}>
                             {sourceData.map((entry, index) => (
                               <Cell key={`cell-${index}`} fill={index === 0 ? '#ef4444' : '#3b82f6'} />
                             ))}
                          </Bar>
                        </BarChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="h-full flex items-center justify-center text-[#555] font-mono text-sm">No data</div>
                      )}
                   </div>
                </div>
                
                <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg p-5 col-span-2">
                  <h3 className="text-xs font-bold text-[#666] uppercase tracking-wider mb-4">Threat Intel Summary</h3>
                  <div className="grid grid-cols-3 gap-4 h-48">
                    <div className="bg-[#111] p-4 rounded border border-[#222] flex flex-col justify-center items-center">
                      <ShieldAlert size={32} className="text-[#10b981] mb-2" />
                      <span className="text-2xl font-mono text-white">{packets.length - malicious}</span>
                      <span className="text-[10px] text-[#666] uppercase tracking-wider mt-1">Clean Packets</span>
                    </div>
                    <div className="bg-red-500/5 p-4 rounded border border-red-500/20 flex flex-col justify-center items-center relative overflow-hidden">
                      <div className="absolute inset-0 bg-red-500/5 animate-pulse"></div>
                      <AlertTriangle size={32} className="text-red-500 mb-2 relative z-10" />
                      <span className="text-2xl font-mono text-red-500 relative z-10">{malicious}</span>
                      <span className="text-[10px] text-red-400/80 uppercase tracking-wider mt-1 relative z-10">Malicious Signatures</span>
                    </div>
                    <div className="bg-[#111] p-4 rounded border border-[#222] flex flex-col justify-center items-center">
                      <Database size={32} className="text-[#3b82f6] mb-2" />
                      <span className="text-2xl font-mono text-white">{(captured * 0.85).toFixed(0)}</span>
                      <span className="text-[10px] text-[#666] uppercase tracking-wider mt-1">Sessions Indexed</span>
                    </div>
                  </div>
                </div>
             </div>
           </div>
        )}

        {activeTab === 'live' && (
          <>
            <section className="flex-1 flex flex-col bg-[#050505] border-r border-[#1f1f1f]">
              <div className="h-12 border-b border-[#1f1f1f] flex items-center justify-between px-4 bg-[#0a0a0a]">
                <div className="flex items-center gap-4">
                  <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Wifi size={14} className={isCapturing ? "text-[#10b981]" : "text-[#555]"} />
                    {t.liveTrafficStream}
                  </h2>
                  <div className="h-4 w-[1px] bg-[#333]"></div>
                  <button 
                    onClick={toggleCapture}
                    className={`flex items-center gap-1.5 px-3 py-1 text-[10px] uppercase font-bold tracking-wider rounded transition-colors ${
                      isCapturing ? 'bg-red-500/20 text-red-500 hover:bg-red-500/30' : 'bg-[#10b981]/20 text-[#10b981] hover:bg-[#10b981]/30'
                    }`}
                  >
                    {isCapturing ? <><Square size={10} fill="currentColor"/> {t.stopCapture}</> : <><Play size={10} fill="currentColor"/> {t.startCapture}</>}
                  </button>
                  <button onClick={() => {setPackets([]); setCaptured(0); setMalicious(0); setSelectedPackets([]);}} className="text-[10px] uppercase text-[#666] hover:text-white px-2">
                    {t.clear}
                  </button>
                  <div className="h-4 w-[1px] bg-[#333]"></div>
                  <button 
                    onClick={downloadFilteredCSV}
                    disabled={filteredPackets.length === 0}
                    className="flex items-center gap-1.5 text-[10px] uppercase text-[#666] hover:text-white px-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Download size={10} /> {t.downloadCsv}
                  </button>
                </div>
                
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <Search size={12} className="absolute left-2 top-1/2 transform -translate-y-1/2 text-[#555]" />
                    <input 
                      ref={searchInputRef}
                      type="text" 
                      placeholder={t.filterPackets}
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="bg-[#111] border border-[#222] rounded pl-7 pr-3 py-1 text-xs text-white focus:outline-none focus:border-[#10b981] w-48 transition-colors"
                    />
                  </div>
                  <button 
                    onClick={() => setIsQueryBuilderOpen(true)}
                    className={`p-1.5 rounded transition-colors ${filterConditions.length > 0 ? 'bg-[#10b981]/20 text-[#10b981] border border-[#10b981]/30' : 'text-[#555] hover:text-white hover:bg-[#222] border border-transparent'}`}
                    title={t.queryBuilder}
                  >
                    <Filter size={14} />
                  </button>
                </div>
              </div>

              <div className="flex-1 flex flex-col relative">
                <div className="grid grid-cols-12 gap-2 px-4 py-2 border-b border-[#1f1f1f] bg-[#0a0a0a] text-[10px] font-bold text-[#666] uppercase tracking-wider">
                  <div className="col-span-1">No.</div>
                  <div className="col-span-2">Time</div>
                  <div className="col-span-2">Source</div>
                  <div className="col-span-2">Destination</div>
                  <div className="col-span-1">Proto</div>
                  <div className="col-span-1">Len</div>
                  <div className="col-span-3">Info</div>
                </div>

                <div className="flex-1 font-mono text-[11px] leading-tight overflow-y-auto custom-scrollbar">
                  {filteredPackets.map((pkt, i) => (
                    <div 
                      key={pkt.id + i} 
                      onClick={() => {
                        if (isCompareMode) {
                          setSelectedPackets(prev => {
                            if (prev.find(p => p.id === pkt.id)) {
                              return prev.filter(p => p.id !== pkt.id);
                            }
                            if (prev.length >= 2) {
                              return [prev[1], pkt];
                            }
                            return [...prev, pkt];
                          });
                        } else {
                          setSelectedPackets([pkt]);
                        }
                      }}
                      className={`grid grid-cols-12 gap-2 px-4 py-1.5 border-b border-[#111] cursor-pointer transition-colors ${
                        selectedPackets.find(p => p.id === pkt.id) ? 'bg-[#10b981]/10 border-[#10b981]/30' : 
                        pkt.isMalicious ? 'bg-red-500/10 hover:bg-red-500/20' : 
                        'hover:bg-[#111]'
                      }`}
                    >
                      <div className="col-span-1 text-[#555]">{captured - i}</div>
                      <div className="col-span-2 text-[#888]">{pkt.time}</div>
                      <div className="col-span-2 text-[#d4d4d4] truncate">{pkt.source}</div>
                      <div className="col-span-2 text-[#d4d4d4] truncate">{pkt.destination}</div>
                      <div className="col-span-1" style={{ color: getProtocolColor(pkt.protocol) }}>{pkt.protocol}</div>
                      <div className="col-span-1 text-[#888]">{pkt.length}</div>
                      <div className={`col-span-3 truncate flex items-center gap-2 ${pkt.isMalicious ? 'text-red-400 font-bold' : 'text-[#888]'}`}>
                        <span className="truncate">{pkt.info}</span>
                        {pkt.note && (
                          <FileText size={10} className="text-[#10b981] flex-shrink-0" />
                        )}
                      </div>
                    </div>
                  ))}
                  {filteredPackets.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-full text-[#555] space-y-4">
                      {isCapturing ? (
                        <>
                           <Activity size={32} className="animate-pulse" />
                           <p className="uppercase text-xs tracking-widest">Waiting for data stream...</p>
                        </>
                      ) : (
                        <>
                           <Square size={32} />
                           <p className="uppercase text-xs tracking-widest">Capture stopped</p>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </section>

            <aside className={`flex flex-col bg-[#050505] transition-all duration-300 ${isCompareMode && selectedPackets.length > 0 ? 'w-[800px]' : 'w-[400px]'}`}>
              <div className="h-12 border-b border-[#1f1f1f] flex items-center justify-between px-4 bg-[#0a0a0a]">
                <h2 className="text-xs font-bold text-white uppercase tracking-wider">{isCompareMode ? 'Packet Comparison' : t.packetDetails}</h2>
                <button 
                  onClick={() => {
                    setIsCompareMode(!isCompareMode);
                    if (isCompareMode && selectedPackets.length > 1) {
                      setSelectedPackets([selectedPackets[0]]);
                    }
                  }}
                  className={`px-3 py-1 text-[10px] font-bold uppercase tracking-wider rounded transition-colors ${isCompareMode ? 'bg-[#3b82f6]/20 text-[#3b82f6]' : 'text-[#666] hover:text-white hover:bg-[#222]'}`}
                >
                  {t.compareMode}
                </button>
              </div>
              
              <div className="flex-1 flex overflow-hidden">
                {selectedPackets.length > 0 ? (
                  <>
                    {selectedPackets.map((packet, idx) => (
                      <div key={packet.id} className={`flex flex-col h-full ${idx === 0 && selectedPackets.length > 1 ? 'border-r border-[#1f1f1f]' : ''} ${isCompareMode && selectedPackets.length > 0 ? (selectedPackets.length > 1 ? 'w-1/2' : 'w-1/2') : 'w-full'}`}>
                        <div className="p-4 border-b border-[#1f1f1f] bg-[#0a0a0a]">
                          <div className="flex items-center justify-between mb-4">
                            <span className="text-xs font-bold text-white">Frame {captured - packets.findIndex(p => p.id === packet.id)}</span>
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold" style={{ backgroundColor: `${getProtocolColor(packet.protocol)}20`, color: getProtocolColor(packet.protocol) }}>
                              {packet.protocol}
                            </span>
                          </div>
                          
                          <div className="space-y-2 text-xs font-mono">
                            <div className="flex justify-between"><span className="text-[#666]">Time:</span> <span className="text-white">{packet.time}</span></div>
                            <div className="flex justify-between"><span className="text-[#666]">Source:</span> <span className="text-blue-400">{packet.source}</span></div>
                            <div className="flex justify-between"><span className="text-[#666]">Destination:</span> <span className="text-purple-400">{packet.destination}</span></div>
                            <div className="flex justify-between"><span className="text-[#666]">Length:</span> <span className="text-white">{packet.length} bytes</span></div>
                          </div>
                          
                          <div className="mt-4 pt-4 border-t border-[#1f1f1f]">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-[10px] font-bold text-[#888] uppercase tracking-wider">Note</span>
                              {packet.note && editingNoteId !== packet.id && (
                                <button onClick={() => { setEditingNoteId(packet.id); setEditingNoteText(packet.note || ''); }} className="text-[#666] hover:text-[#10b981] transition-colors" title={t.editNote}>
                                  <Edit2 size={12} />
                                </button>
                              )}
                            </div>
                            
                            {editingNoteId === packet.id ? (
                              <div className="flex flex-col gap-2">
                                <textarea
                                  value={editingNoteText}
                                  onChange={(e) => setEditingNoteText(e.target.value)}
                                  placeholder={t.notePlaceholder}
                                  className="bg-[#111] border border-[#333] rounded p-2 text-xs text-white focus:outline-none focus:border-[#10b981] min-h-[60px] resize-none"
                                />
                                <div className="flex justify-end gap-2">
                                  <button onClick={() => setEditingNoteId(null)} className="px-2 py-1 text-[10px] text-[#888] hover:text-white transition-colors">
                                    {t.cancel}
                                  </button>
                                  <button onClick={() => handleUpdateNote(packet.id, editingNoteText)} className="px-2 py-1 text-[10px] bg-[#10b981]/20 text-[#10b981] hover:bg-[#10b981]/30 rounded transition-colors flex items-center gap-1">
                                    <Save size={10} /> {t.saveNote}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div>
                                {packet.note ? (
                                  <p className="text-xs text-[#d4d4d4] whitespace-pre-wrap">{packet.note}</p>
                                ) : (
                                  <button onClick={() => { setEditingNoteId(packet.id); setEditingNoteText(''); }} className="text-[10px] text-[#666] hover:text-[#10b981] transition-colors flex items-center gap-1 border border-dashed border-[#333] rounded px-2 py-1.5 w-full justify-center">
                                    <Edit2 size={10} /> {t.addNote}
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                        
                        <div className="flex-1 flex flex-col overflow-y-auto custom-scrollbar">
                          <div className="border-b border-[#1f1f1f]">
                            <div className="px-4 py-2 bg-[#111] text-[10px] font-bold text-[#888] uppercase tracking-wider flex items-center gap-2">
                              <SquareActivity size={12}/> {t.decodedPayload}
                            </div>
                            <div className="p-4 font-mono text-[10px] text-[#a0aec0] space-y-2">
                              {packet.decoded?.map((line, l_idx) => (
                                <div key={l_idx} className={`${line.includes('ALERT') ? 'text-red-400 font-bold bg-red-500/10 p-1 -mx-1 rounded' : ''}`}>
                                  {line.startsWith('Internet') || line.startsWith('Transmission') ? (
                                    <span><span className="text-[#555] mr-2">▶</span> {line}</span>
                                  ) : (
                                    <span><span className="text-[#555] mr-2 invisible">▶</span> {line}</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                          
                          <div className="flex-1 flex flex-col">
                            <div className="px-4 py-2 bg-[#111] text-[10px] font-bold text-[#888] uppercase tracking-wider border-b border-[#1f1f1f] flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Code size={12}/> {t.payloadData}
                              </div>
                              <div className="flex bg-[#222] rounded p-0.5">
                                <button 
                                  onClick={() => setPayloadViewMode('hex')}
                                  className={`px-2 py-0.5 rounded transition-colors ${payloadViewMode === 'hex' ? 'bg-[#333] text-white' : 'text-[#666] hover:text-[#999]'}`}
                                >
                                  {t.hexDump}
                                </button>
                                <button 
                                  onClick={() => setPayloadViewMode('ascii')}
                                  className={`px-2 py-0.5 rounded transition-colors ${payloadViewMode === 'ascii' ? 'bg-[#333] text-white' : 'text-[#666] hover:text-[#999]'}`}
                                >
                                  {t.asciiView}
                                </button>
                              </div>
                            </div>
                            <div className="p-4 font-mono text-[10px] text-[#555] whitespace-pre-wrap leading-relaxed flex-1 overflow-y-auto">
                              {payloadViewMode === 'hex' ? (
                                packet.hex || "0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00\n0010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00"
                              ) : (
                                parseHexDumpToAscii(packet.hex || "") || "No payload"
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                    
                    {isCompareMode && selectedPackets.length === 1 && (
                      <div className="flex flex-col items-center justify-center h-full text-center p-8 w-1/2">
                        <FileSearch size={32} className="text-[#222] mb-4" />
                        <h3 className="text-[#888] font-bold mb-2 uppercase tracking-wider text-xs">{t.selectSecondPacket}</h3>
                        <p className="text-[#555] text-[10px] leading-relaxed">{t.selectSecondPacketDesc}</p>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center p-8 w-full">
                    <FileSearch size={48} className="text-[#222] mb-4" />
                    <h3 className="text-[#888] font-bold mb-2 uppercase tracking-wider">{t.noPacketSelected}</h3>
                    <p className="text-[#555] text-xs leading-relaxed">{t.selectPacketDesc}</p>
                  </div>
                )}
              </div>
            </aside>
          </>
        )}

        {activeTab === 'topology' && (
          <div className="flex-1 p-8 bg-[#050505] overflow-y-auto flex flex-col relative">
            <h2 className="text-xl font-bold text-white mb-6 uppercase tracking-tight">{t.topology}</h2>
            <div className="w-full flex-1 min-h-[600px] bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg relative overflow-hidden shadow-[inset_0_0_50px_rgba(0,0,0,0.8)]">
              <div className="absolute inset-0 opacity-10 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at center, #10b981 1px, transparent 1px)', backgroundSize: '30px 30px' }}></div>
              <motion.div 
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 1 }}
                className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-center z-10"
              >
                <motion.div
                  animate={{ 
                    boxShadow: ['0 0 15px rgba(16,185,129,0.2)', '0 0 30px rgba(16,185,129,0.6)', '0 0 15px rgba(16,185,129,0.2)'],
                  }}
                  transition={{ repeat: Infinity, duration: 2 }}
                  className="rounded-full bg-[#111] p-4 inline-block mb-4 border border-[#10b981]/30"
                >
                  <Globe size={48} className="text-[#10b981]" />
                </motion.div>
                <p className="text-[#888] font-mono text-xs uppercase tracking-widest border border-[#333] px-4 py-2 rounded-full bg-[#111] shadow-[0_0_20px_rgba(16,185,129,0.2)]">
                  Core Router
                </p>
              </motion.div>
              
              {/* Dynamic Animated Nodes */}
              {uniqueNodes.length > 0 ? uniqueNodes.map((node, i) => {
                const angle = (i * (360 / uniqueNodes.length)) * (Math.PI / 180);
                const radius = 35; // %
                const top = 50 + Math.sin(angle) * radius;
                const left = 50 + Math.cos(angle) * radius;
                const colorClass = node.isMalicious ? 'bg-red-500 shadow-red-500' : 'bg-blue-500 shadow-blue-500';
                const textClass = node.isMalicious ? 'text-red-400' : 'text-blue-400';
                const strokeColor = node.isMalicious ? '#ef4444' : '#3b82f6';

                return (
                  <React.Fragment key={node.ip}>
                    <motion.div 
                      initial={{ opacity: 0, scale: 0 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.1, duration: 0.5 }}
                      className="absolute group z-10 transform -translate-x-1/2 -translate-y-1/2 text-center" 
                      style={{ top: `${top}%`, left: `${left}%` }}
                    >
                      <motion.div 
                        animate={{ scale: [1, 1.2, 1] }}
                        transition={{ repeat: Infinity, duration: 2 + (i % 3) * 0.5 }}
                        className={`w-4 h-4 ${colorClass} rounded-full shadow-[0_0_15px_currentColor] mx-auto`}
                      ></motion.div>
                      <div className={`mt-2 text-[10px] font-mono ${textClass} bg-[#111] px-2 py-1 rounded border border-[#222] whitespace-nowrap`}>
                        {node.ip}
                        <br/>
                        <span className="text-[#666]">{(node.count / 1024).toFixed(1)} KB</span>
                      </div>
                    </motion.div>
                  </React.Fragment>
                );
              }) : (
                <div className="absolute top-1/4 left-1/2 transform -translate-x-1/2 text-center z-10 text-[#555] font-mono text-sm">
                  {t.noPacketSelected}
                </div>
              )}
              
              {/* Lines (SVG) with flowing packets */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none z-0" style={{ opacity: 0.6 }}>
                {uniqueNodes.map((node, i) => {
                  const angle = (i * (360 / uniqueNodes.length)) * (Math.PI / 180);
                  const radius = 35; // %
                  const top = 50 + Math.sin(angle) * radius;
                  const left = 50 + Math.cos(angle) * radius;
                  const strokeColor = node.isMalicious ? '#ef4444' : '#3b82f6';
                  
                  return (
                    <motion.line 
                      key={node.ip}
                      x1="50%" 
                      y1="50%" 
                      x2={`${left}%`} 
                      y2={`${top}%`} 
                      stroke={strokeColor} 
                      strokeWidth={node.isMalicious ? "2" : "1"} 
                      strokeDasharray="4 4" 
                      animate={{ strokeDashoffset: [0, -20] }} 
                      transition={{ repeat: Infinity, duration: 1 + (i % 2), ease: "linear" }} 
                    />
                  );
                })}
              </svg>
            </div>
          </div>
        )}

        {activeTab === 'analyzer' && (
          <div className="flex-1 flex flex-col items-center justify-center bg-[#050505] p-8">
            <h2 className="text-2xl font-bold text-white mb-6 uppercase tracking-tight">{t.offlinePcapAnalysis}</h2>
            <div className="max-w-2xl w-full p-10 bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg text-center shadow-[0_0_50px_rgba(16,185,129,0.05)] relative overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-[#10b981] to-transparent opacity-50"></div>
              <Upload size={64} className="mx-auto text-[#10b981] mb-6 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
              <p className="text-sm text-[#888] mb-8 leading-relaxed font-mono">
                {t.uploadPcapDesc}
              </p>
              
              <div className="w-full bg-[#050505] border-2 border-dashed border-[#333] rounded-lg p-10 flex flex-col items-center justify-center hover:border-[#10b981]/50 transition-colors cursor-pointer group mb-6">
                <FileSearch size={32} className="text-[#444] group-hover:text-[#10b981] mb-4 transition-colors" />
                <label className="cursor-pointer group flex flex-col items-center w-full">
                  <div className="bg-[#10b981]/10 text-[#10b981] border border-[#10b981]/30 px-8 py-4 rounded text-sm font-bold uppercase tracking-wider group-hover:bg-[#10b981]/20 transition-all shadow-[0_0_15px_rgba(16,185,129,0.1)]">
                    {t.selectPcapFile}
                  </div>
                  <input type="file" accept=".pcap,.pcapng" className="hidden" onChange={handleFileUpload} />
                  <p className="text-[10px] text-[#555] uppercase mt-4 font-mono">Supports .pcap, .pcapng (Max 5GB)</p>
                </label>
              </div>

              <div className="flex items-center justify-center gap-4 mb-6 pt-6 border-t border-[#1f1f1f]">
                <button 
                  onClick={downloadJSON}
                  disabled={packets.length === 0}
                  className="flex items-center gap-2 px-4 py-2 bg-[#111] hover:bg-[#222] text-xs font-bold text-[#d4d4d4] uppercase tracking-wider rounded border border-[#222] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Download size={14} /> {t.downloadJson}
                </button>
                <button 
                  onClick={downloadCSV}
                  disabled={packets.length === 0}
                  className="flex items-center gap-2 px-4 py-2 bg-[#111] hover:bg-[#222] text-xs font-bold text-[#d4d4d4] uppercase tracking-wider rounded border border-[#222] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Download size={14} /> {t.downloadCsv}
                </button>
              </div>

              <div className="grid grid-cols-3 gap-4 text-left">
                <div className="bg-[#111] border border-[#222] p-4 rounded">
                   <h4 className="text-[10px] uppercase font-bold text-[#666] mb-1">Deep Scanning</h4>
                   <p className="text-xs text-[#888] font-mono">Heuristic + Signature</p>
                </div>
                <div className="bg-[#111] border border-[#222] p-4 rounded">
                   <h4 className="text-[10px] uppercase font-bold text-[#666] mb-1">Decryption</h4>
                   <p className="text-xs text-[#888] font-mono">TLS / SSL Parsing</p>
                </div>
                <div className="bg-[#111] border border-[#222] p-4 rounded">
                   <h4 className="text-[10px] uppercase font-bold text-[#666] mb-1">Export</h4>
                   <p className="text-xs text-[#888] font-mono">JSON / CSV format</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="flex-1 p-8 bg-[#050505] overflow-y-auto">
             <h2 className="text-xl font-bold text-white mb-6 uppercase tracking-tight">{t.activeThreats}</h2>
             
             <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
               <div className="lg:col-span-2 bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg overflow-hidden flex flex-col">
                 <div className="px-5 py-4 border-b border-[#1f1f1f] bg-[#111] flex items-center justify-between">
                   <h3 className="text-xs font-bold text-white uppercase tracking-wider">{t.threatLog}</h3>
                   <span className="bg-red-500/20 text-red-500 text-[10px] px-2 py-0.5 rounded font-bold">{malicious} DETECTED</span>
                 </div>
                 <div className="p-0 overflow-y-auto max-h-[500px]">
                   <table className="w-full text-left text-[11px] font-mono">
                     <thead className="bg-[#050505] text-[#666] sticky top-0">
                       <tr>
                         <th className="px-4 py-2 font-normal uppercase tracking-wider">Time</th>
                         <th className="px-4 py-2 font-normal uppercase tracking-wider">Source</th>
                         <th className="px-4 py-2 font-normal uppercase tracking-wider">Destination</th>
                         <th className="px-4 py-2 font-normal uppercase tracking-wider">Signature Match</th>
                       </tr>
                     </thead>
                     <tbody className="divide-y divide-[#1f1f1f]">
                       {packets.filter(p => p.isMalicious).length > 0 ? (
                         packets.filter(p => p.isMalicious).map((p, i) => (
                           <tr key={i} className="hover:bg-[#111] transition-colors">
                             <td className="px-4 py-3 text-[#888]">{p.time}</td>
                             <td className="px-4 py-3 text-white">{p.source}</td>
                             <td className="px-4 py-3 text-white">{p.destination}</td>
                             <td className="px-4 py-3 text-red-400">{p.info}</td>
                           </tr>
                         ))
                       ) : (
                         <tr>
                           <td colSpan={4} className="px-4 py-8 text-center text-[#555]">
                             No malicious signatures detected in current stream.
                           </td>
                         </tr>
                       )}
                     </tbody>
                   </table>
                 </div>
               </div>
               
               <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg p-5">
                 <h3 className="text-xs font-bold text-[#666] uppercase tracking-wider mb-4 flex items-center gap-2">
                   <ShieldAlert size={14} /> {t.threatSignatures}
                 </h3>
                 <ul className="space-y-3 font-mono text-[10px]">
                   <li className="flex justify-between items-center p-2 bg-[#111] rounded border border-[#222]">
                     <span className="text-[#a0aec0]">SQL Injection</span>
                     <span className="text-red-400 font-bold">ACTIVE</span>
                   </li>
                   <li className="flex justify-between items-center p-2 bg-[#111] rounded border border-[#222]">
                     <span className="text-[#a0aec0]">C2 Beaconing</span>
                     <span className="text-red-400 font-bold">ACTIVE</span>
                   </li>
                   <li className="flex justify-between items-center p-2 bg-[#111] rounded border border-[#222]">
                     <span className="text-[#a0aec0]">DNS Tunneling</span>
                     <span className="text-[#10b981] font-bold">MONITORING</span>
                   </li>
                   <li className="flex justify-between items-center p-2 bg-[#111] rounded border border-[#222]">
                     <span className="text-[#a0aec0]">SYN Flood</span>
                     <span className="text-red-400 font-bold">ACTIVE</span>
                   </li>
                   <li className="flex justify-between items-center p-2 bg-[#111] rounded border border-[#222]">
                     <span className="text-[#a0aec0]">Log4Shell</span>
                     <span className="text-[#10b981] font-bold">MONITORING</span>
                   </li>
                 </ul>
               </div>
             </div>
          </div>
        )}

        {activeTab === 'agent' && (
          <div className="flex-1 p-8 bg-[#050505] overflow-y-auto">
             <div className="max-w-3xl mx-auto">
               <h2 className="text-2xl font-bold text-white mb-2 uppercase tracking-tight">{t.agentSetup}</h2>
               <p className="text-[#888] text-sm mb-6">{t.agentSetupSubtitle}</p>
               
               <div className="bg-[#111] border border-[#1f1f1f] rounded-lg p-5 mb-8">
                 <h3 className="text-sm font-bold text-white mb-3 uppercase tracking-wider text-[#10b981]">{t.agentSetupInstTitle}</h3>
                 <ul className="space-y-2 text-xs text-[#a0aec0] font-mono leading-relaxed">
                   <li>{t.agentSetupStep1}</li>
                   <li>{t.agentSetupStep2}</li>
                   <li>{t.agentSetupStep3}</li>
                   <li>{t.agentSetupStep4}</li>
                 </ul>
               </div>

               <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg overflow-hidden mb-8">
                <div className="bg-[#111] px-5 py-3 border-b border-[#1f1f1f] flex items-center justify-between">
                  <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Terminal size={14} /> {t.localAgentConnection}
                  </h2>
                </div>
                <div className="p-6">
                  <div className="space-y-4 mb-6">
                    <label className="text-[10px] text-[#666] uppercase tracking-wider">WebSocket Endpoint URL</label>
                    <input 
                      type="text" 
                      value={wsEndpoint}
                      onChange={(e) => setWsEndpoint(e.target.value)}
                      disabled={isCapturing}
                      className="w-full bg-[#111] border border-[#333] rounded px-4 py-3 text-sm font-mono text-[#10b981] focus:outline-none focus:border-[#10b981] disabled:opacity-50"
                      placeholder="ws://127.0.0.1:8080"
                    />
                    
                    {wsError && (
                      <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-[11px] text-red-400 font-mono">
                        {wsError}
                      </div>
                    )}
                    <p className="text-[11px] text-[#555] leading-relaxed">
                      {t.connectToLocalDPI}
                    </p>
                  </div>
                  
                  <div className="flex justify-end pt-4 border-t border-[#1f1f1f]">
                    <button
                      onClick={isCapturing || connectionStatus === 'connected' ? disconnectWebSocket : connectWebSocket}
                      className={`px-6 py-2 rounded text-xs font-bold uppercase tracking-wider transition-colors ${
                        connectionStatus === 'connected' || isCapturing 
                          ? 'bg-red-500 hover:bg-red-600 text-white' 
                          : 'bg-[#10b981] hover:bg-[#059669] text-white'
                      }`}
                    >
                      {connectionStatus === 'connected' || isCapturing ? t.disconnect : t.connect}
                    </button>
                  </div>
                </div>
               </div>

               <div className="bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg overflow-hidden">
                 <div className="px-5 py-4 border-b border-[#1f1f1f] bg-[#111] flex justify-between items-center">
                   <h3 className="text-xs font-bold text-white uppercase tracking-wider">Python DPI Agent Example</h3>
                   <div className="flex gap-2">
                     <button 
                       onClick={() => navigator.clipboard.writeText(pythonCodeString)}
                       className="text-[10px] uppercase font-bold tracking-wider text-[#10b981] hover:text-[#059669] px-3 py-1 border border-[#10b981]/30 rounded"
                     >
                       Copy
                     </button>
                     <a 
                       href={URL.createObjectURL(new Blob([pythonCodeString], {type: 'text/x-python'}))}
                       download="agent.py"
                       className="text-[10px] uppercase font-bold tracking-wider text-[#10b981] hover:text-[#059669] px-3 py-1 border border-[#10b981]/30 rounded bg-[#10b981]/10"
                     >
                       Download agent.py
                     </a>
                   </div>
                 </div>
                 <div className="p-0 relative">
                   <pre className="bg-[#050505] p-6 text-[#a0aec0] font-mono text-xs leading-relaxed overflow-x-auto custom-scrollbar">
{pythonCodeString}
                   </pre>
                 </div>
               </div>
             </div>
          </div>
        )}

        {isQueryBuilderOpen && (
          <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="bg-[#050505] border border-[#1f1f1f] rounded-lg shadow-2xl w-full max-w-3xl flex flex-col overflow-hidden">
              <div className="h-12 border-b border-[#1f1f1f] flex items-center justify-between px-6 bg-[#0a0a0a]">
                <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Filter size={16} className="text-[#10b981]" />
                  {t.queryBuilder}
                </h2>
                <button onClick={() => setIsQueryBuilderOpen(false)} className="text-[#666] hover:text-white transition-colors">
                  <Square size={14} className="fill-current" />
                </button>
              </div>
              
              <div className="p-6 overflow-y-auto max-h-[60vh] space-y-4">
                {filterConditions.length === 0 ? (
                  <div className="text-center py-8 text-[#555] font-mono text-xs">
                    No active conditions.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {filterConditions.map((cond, idx) => (
                      <div key={cond.id} className="flex items-center gap-3 bg-[#111] border border-[#222] p-3 rounded">
                        <span className="text-[#666] font-bold text-[10px] w-8 text-center">{idx === 0 ? 'WHERE' : 'AND'}</span>
                        
                        <select 
                          value={cond.field}
                          onChange={(e) => {
                            const newConds = [...filterConditions];
                            const oldField = newConds[idx].field;
                            newConds[idx].field = e.target.value as any;
                            if (e.target.value === 'length' && oldField !== 'length') {
                              newConds[idx].operator = 'equals';
                              newConds[idx].value = '';
                            } else if (e.target.value !== 'length' && oldField === 'length') {
                              newConds[idx].operator = 'contains';
                              newConds[idx].value = '';
                            }
                            setFilterConditions(newConds);
                          }}
                          className="bg-[#0a0a0a] border border-[#333] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-[#10b981]"
                        >
                          <option value="source">{t.source}</option>
                          <option value="destination">{t.destination}</option>
                          <option value="protocol">{t.protocol}</option>
                          <option value="length">{t.length}</option>
                          <option value="info">{t.info}</option>
                        </select>

                        <select 
                          value={cond.operator}
                          onChange={(e) => {
                            const newConds = [...filterConditions];
                            newConds[idx].operator = e.target.value as any;
                            setFilterConditions(newConds);
                          }}
                          className="bg-[#0a0a0a] border border-[#333] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-[#10b981]"
                        >
                          {cond.field === 'length' ? (
                            <>
                              <option value="equals">{t.equals}</option>
                              <option value="greater_than">{t.greater_than}</option>
                              <option value="less_than">{t.less_than}</option>
                            </>
                          ) : (
                            <>
                              <option value="contains">{t.contains}</option>
                              <option value="equals">{t.equals}</option>
                              <option value="starts_with">{t.starts_with}</option>
                              <option value="ends_with">{t.ends_with}</option>
                            </>
                          )}
                        </select>
                        
                        <input
                          type={cond.field === 'length' ? 'number' : 'text'}
                          value={cond.value}
                          onChange={(e) => {
                            const newConds = [...filterConditions];
                            newConds[idx].value = e.target.value;
                            setFilterConditions(newConds);
                          }}
                          placeholder={t.value}
                          className="flex-1 bg-[#0a0a0a] border border-[#333] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-[#10b981]"
                        />
                        
                        <button 
                          onClick={() => {
                            setFilterConditions(filterConditions.filter(c => c.id !== cond.id));
                          }}
                          className="p-1.5 text-red-500 hover:bg-red-500/20 rounded transition-colors"
                        >
                          <Square size={14} className="fill-current" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                
                <button 
                  onClick={() => {
                    setFilterConditions([...filterConditions, { id: Math.random().toString(36).substr(2, 9), field: 'source', operator: 'contains', value: '' }]);
                  }}
                  className="px-4 py-2 bg-[#111] hover:bg-[#222] text-[#10b981] text-xs font-bold uppercase tracking-wider rounded border border-[#222] hover:border-[#10b981]/50 transition-colors w-full flex items-center justify-center gap-2"
                >
                  <SquareActivity size={14} /> {t.addCondition}
                </button>
              </div>
              
              <div className="p-4 border-t border-[#1f1f1f] bg-[#0a0a0a] flex justify-end gap-3">
                <button 
                  onClick={() => setFilterConditions([])}
                  className="px-6 py-2 text-xs font-bold text-[#666] hover:text-white uppercase tracking-wider transition-colors"
                >
                  {t.clearFilters}
                </button>
                <button 
                  onClick={() => setIsQueryBuilderOpen(false)}
                  className="px-6 py-2 bg-[#10b981] hover:bg-[#059669] text-[#050505] text-xs font-bold uppercase tracking-wider rounded transition-colors"
                >
                  {t.applyFilters}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="h-6 border-t border-[#1f1f1f] bg-[#050505] flex items-center justify-between px-6 z-10 text-[9px] text-[#555] uppercase tracking-wider font-mono">
        <div>{t.copyright}</div>
      </footer>
    </div>
  );
}
