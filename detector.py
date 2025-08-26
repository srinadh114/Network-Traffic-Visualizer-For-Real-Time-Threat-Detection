from collections import defaultdict, deque
import time
from scapy.all import TCP, UDP, ICMP, IP, ARP, Ether  # Import necessary layers

# --- Configuration (Could be moved to a separate JSON/YAML file later) ---
CONFIG = {
    "tcp_syn_scan": {"window_secs": 10, "threshold_syn_pkts": 15, "target_port_variety_threshold": 5},
    "tcp_connect_scan": {"window_secs": 10, "threshold_connections": 10},  # Requires more state
    "udp_scan": {"window_secs": 10, "threshold_udp_pkts": 20, "target_port_variety_threshold": 5},
    "icmp_flood": {"window_secs": 5, "threshold_pkts": 30},
    "suspicious_tcp_flags": True,  # Enable/disable this check
    "arp_spoof_detection": True,
    # Payload signatures (very basic examples)
    "payload_signatures": [
        {"name": "Directory Traversal Attempt", "pattern": b"../../", "protocols": ["TCP"], "ports": [80, 443, 8080]},
        {"name": "Basic SQLi Attempt", "pattern": b"' OR '1'='1", "protocols": ["TCP"], "ports": [80, 443, 8080]},
    ],
    "suspicious_user_agents": [  # For HTTP traffic
        b"masscan", b"sqlmap", b"Nmap Scripting Engine",
    ],
    "known_bad_ips": ["1.2.3.4", "5.6.7.8"],  # Example list
}

# --- State Variables ---
# For Port Scan Detection
ip_tcp_syn_timestamps = defaultdict(lambda: defaultdict(list))  # ip_src -> {target_ip_port: [timestamps]}
ip_udp_packet_timestamps = defaultdict(lambda: defaultdict(list))  # ip_src -> {target_ip_port: [timestamps]}
# For ICMP Flood
icmp_timestamps = defaultdict(list)
# For ARP Spoofing
arp_table = {}  # ip -> {"mac": mac_address, "timestamp": last_seen_time}
potential_arp_spoofs = defaultdict(int)  # (attacker_mac, victim_ip) -> count

# For more advanced connection tracking (example)
active_connections = {}  # (src_ip, sport, dst_ip, dport, proto) -> {start_time, packet_count, byte_count, last_seen}


# --- Helper Functions ---
def _prune_timestamps(timestamp_list, window_secs):
    current_time = time.time()
    return [t for t in timestamp_list if current_time - t < window_secs]


def get_payload(packet):
    if packet.haslayer(TCP) and packet[TCP].payload:
        return bytes(packet[TCP].payload)
    if packet.haslayer(UDP) and packet[UDP].payload:
        return bytes(packet[UDP].payload)
    return None


# --- Detection Modules ---
def detect_tcp_scans(packet, ip_src, ip_dst, dport):
    alerts = []
    current_time = time.time()
    target_key = f"{ip_dst}:{dport}"

    # TCP SYN Scan (simplified: count SYNs to diverse ports from one source)
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # SYN flag
        ip_tcp_syn_timestamps[ip_src][target_key].append(current_time)

        # Prune old entries for this specific source
        relevant_targets_for_src = {}
        total_syns_in_window = 0
        distinct_ports_targeted = set()

        for tgt, ts_list in ip_tcp_syn_timestamps[ip_src].items():
            pruned_ts = _prune_timestamps(ts_list, CONFIG["tcp_syn_scan"]["window_secs"])
            if pruned_ts:
                relevant_targets_for_src[tgt] = pruned_ts
                total_syns_in_window += len(pruned_ts)
                # Assuming tgt is "ip:port", extract port
                try:
                    distinct_ports_targeted.add(int(tgt.split(':')[1]))
                except:
                    pass  # ignore malformed target_key for port count

        ip_tcp_syn_timestamps[ip_src] = relevant_targets_for_src  # Update with pruned data

        if total_syns_in_window > CONFIG["tcp_syn_scan"]["threshold_syn_pkts"] and \
                len(distinct_ports_targeted) > CONFIG["tcp_syn_scan"]["target_port_variety_threshold"]:
            alerts.append(
                f"[TCP SYN Scan] High rate of SYNs ({total_syns_in_window}) to {len(distinct_ports_targeted)} distinct ports from {ip_src}.")
            # ip_tcp_syn_timestamps[ip_src].clear() # Optionally reset after alert to reduce noise

    # TODO: Add TCP Connect Scan (requires tracking full handshakes)
    return alerts


def detect_udp_scans(packet, ip_src, ip_dst, dport):
    alerts = []
    current_time = time.time()
    target_key = f"{ip_dst}:{dport}"

    ip_udp_packet_timestamps[ip_src][target_key].append(current_time)

    relevant_targets_for_src = {}
    total_udp_in_window = 0
    distinct_ports_targeted = set()

    for tgt, ts_list in ip_udp_packet_timestamps[ip_src].items():
        pruned_ts = _prune_timestamps(ts_list, CONFIG["udp_scan"]["window_secs"])
        if pruned_ts:
            relevant_targets_for_src[tgt] = pruned_ts
            total_udp_in_window += len(pruned_ts)
            try:
                distinct_ports_targeted.add(int(tgt.split(':')[1]))
            except:
                pass

    ip_udp_packet_timestamps[ip_src] = relevant_targets_for_src

    if total_udp_in_window > CONFIG["udp_scan"]["threshold_udp_pkts"] and \
            len(distinct_ports_targeted) > CONFIG["udp_scan"]["target_port_variety_threshold"]:
        alerts.append(
            f"[UDP Scan] High rate of UDP packets ({total_udp_in_window}) to {len(distinct_ports_targeted)} distinct ports from {ip_src}.")
        # ip_udp_packet_timestamps[ip_src].clear()
    return alerts


def detect_suspicious_tcp_flags(packet, ip_src, ip_dst, dport):
    if not CONFIG["suspicious_tcp_flags"]:
        return []
    alerts = []
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == "F":  # FIN Scan
            alerts.append(f"[Suspicious TCP Flags] FIN Scan detected from {ip_src} to {ip_dst}:{dport}")
        elif flags == 0:  # NULL Scan
            alerts.append(f"[Suspicious TCP Flags] NULL Scan detected from {ip_src} to {ip_dst}:{dport}")
        elif flags == "FPU":  # XMAS Scan (FIN, PSH, URG)
            alerts.append(f"[Suspicious TCP Flags] XMAS Scan detected from {ip_src} to {ip_dst}:{dport}")
        # Potentially add others like ACK scan if specific patterns are identified
    return alerts


def detect_icmp_flood(packet, ip_src):
    alerts = []
    current_time = time.time()
    icmp_timestamps[ip_src].append(current_time)
    icmp_timestamps[ip_src] = _prune_timestamps(icmp_timestamps[ip_src], CONFIG["icmp_flood"]["window_secs"])

    if len(icmp_timestamps[ip_src]) > CONFIG["icmp_flood"]["threshold_pkts"]:
        alerts.append(f"[ICMP Flood Likely] Excessive ICMP from {ip_src} ({len(icmp_timestamps[ip_src])} in window).")
        # icmp_timestamps[ip_src] = [] # Optionally reset
    return alerts


def detect_arp_spoofing(packet):
    if not CONFIG["arp_spoof_detection"] or not packet.haslayer(ARP):
        return []

    alerts = []
    arp_layer = packet[ARP]
    current_time = time.time()

    # We are interested in ARP replies (op=2) or gratuitous ARPs (op=1 or 2 with spa=tpa)
    # For simplicity, let's consider op=2 (is-at) for now.
    # A more robust check involves checking for gratuitous ARP for IP conflicts too.
    if arp_layer.op == 2:  # is-at (reply)
        sender_mac = arp_layer.hwsrc
        sender_ip = arp_layer.psrc

        if sender_ip in arp_table:
            known_mac = arp_table[sender_ip]["mac"]
            if known_mac != sender_mac:
                # MAC address for this IP has changed! Potential spoof.
                alert_msg = (f"[ARP Spoof Alert] IP {sender_ip} was {known_mac}, "
                             f"now claimed by {sender_mac}. Original packet: {packet[Ether].src} -> {packet[Ether].dst}")
                alerts.append(alert_msg)
                # You might want to track frequency or get more confirmation
                # For example, only alert if it happens multiple times or if packet[Ether].src (source of ethernet frame) != sender_mac
                if packet[Ether].src != sender_mac:
                    alerts.append(
                        f"  [ARP Spoof Detail] Ethernet source MAC ({packet[Ether].src}) differs from ARP sender MAC ({sender_mac}).")

        arp_table[sender_ip] = {"mac": sender_mac, "timestamp": current_time}

    # TODO: Add detection for rapid ARP requests for many IPs (ARP scanning)
    # TODO: Clean up old entries from arp_table
    return alerts


def detect_payload_signatures(packet):
    alerts = []
    payload = get_payload(packet)
    if not payload:
        return []

    # Basic User-Agent check in HTTP (assuming unencrypted)
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):  # Basic HTTP check
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            for ua_sig in CONFIG["suspicious_user_agents"]:
                if ua_sig.decode('utf-8', errors='ignore').lower() in payload_str:  # Case-insensitive check for UA
                    alerts.append(
                        f"[Suspicious User-Agent] Detected '{ua_sig.decode()}' from {packet[IP].src if IP in packet else 'N/A'}.")
        except Exception:
            pass  # Ignore decoding errors

    # Basic signature matching
    for sig in CONFIG["payload_signatures"]:
        proto_match = False
        if "TCP" in sig["protocols"] and packet.haslayer(TCP):
            if not sig.get("ports") or packet[TCP].dport in sig["ports"] or packet[TCP].sport in sig["ports"]:
                proto_match = True
        if "UDP" in sig["protocols"] and packet.haslayer(UDP):
            if not sig.get("ports") or packet[UDP].dport in sig["ports"] or packet[UDP].sport in sig["ports"]:
                proto_match = True

        if proto_match and sig["pattern"] in payload:
            alerts.append(
                f"[{sig['name']}] Detected pattern '{sig['pattern'][:20].decode('utf-8', 'ignore')}...' from {packet[IP].src if IP in packet else 'N/A'}.")
    return alerts


def detect_known_bad_actors(packet):
    alerts = []
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_src in CONFIG["known_bad_ips"]:
            alerts.append(f"[Known Bad IP] Connection from known bad source: {ip_src}")
        if ip_dst in CONFIG["known_bad_ips"]:
            alerts.append(f"[Known Bad IP] Connection to known bad destination: {ip_dst}")
    return alerts


# --- Main Analysis Function ---
def analyze_packet(packet):
    all_alerts = []

    # Common variables
    ip_src, ip_dst, sport, dport = None, None, None, None
    is_ip = packet.haslayer(IP)
    if is_ip:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport

    # --- Call detection modules ---
    if is_ip:
        if packet.haslayer(TCP):
            all_alerts.extend(detect_tcp_scans(packet, ip_src, ip_dst, dport))
            all_alerts.extend(detect_suspicious_tcp_flags(packet, ip_src, ip_dst, dport))
        elif packet.haslayer(UDP):
            all_alerts.extend(detect_udp_scans(packet, ip_src, ip_dst, dport))
        elif packet.haslayer(ICMP):
            all_alerts.extend(detect_icmp_flood(packet, ip_src))

        all_alerts.extend(detect_known_bad_actors(packet))

    # Layer 2 detection
    all_alerts.extend(detect_arp_spoofing(packet))  # Works on ARP packets

    # Payload based (can be slow, do last or selectively)
    all_alerts.extend(detect_payload_signatures(packet))

    if all_alerts:
        return "; ".join(all_alerts)
    return None


# --- Periodic Cleanup (Optional, can be called from visualizer or a separate thread) ---
def periodic_cleanup():
    current_time = time.time()
    # Example: Clean up old ARP entries
    keys_to_delete = [ip for ip, data in arp_table.items() if current_time - data["timestamp"] > 3600]  # 1 hour
    for key in keys_to_delete:
        del arp_table[key]

    # Clean other state variables similarly if they grow too large without natural pruning
    print("[Detector] Periodic cleanup run.")