#!/usr/bin/env python3
"""
Basic Network Sniffer
----------------------
Educational tool for capturing and inspecting network packets.
Displays Source IP, Destination IP, Protocol, and (safe) payload preview.

Cross-platform: Works on Windows (requires Npcap) and Linux (requires root).
Author: [Your Name] — Cybersecurity Internship Project
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import sys
import datetime

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
PACKET_COUNT = 0          # 0 = sniff indefinitely until Ctrl+C
INTERFACE = None          # None = scapy picks default interface
PAYLOAD_PREVIEW_LEN = 50  # Limit how many bytes of payload we print


def get_protocol_name(packet):
    """
    Determine the transport-layer protocol name from the packet.
    Returns a string like 'TCP', 'UDP', 'ICMP', or 'OTHER'.
    """
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def safe_payload_preview(packet):
    """
    Safely extract a short, printable preview of the payload.
    Non-printable bytes are replaced to avoid garbling the console
    or accidentally executing/interpreting control characters.
    """
    if packet.haslayer(Raw):
        try:
            raw_bytes = bytes(packet[Raw].load)
            snippet = raw_bytes[:PAYLOAD_PREVIEW_LEN]
            # Replace non-printable characters with '.'
            printable = ''.join(
                chr(b) if 32 <= b <= 126 else '.' for b in snippet
            )
            suffix = "..." if len(raw_bytes) > PAYLOAD_PREVIEW_LEN else ""
            return printable + suffix
        except Exception as e:
            return f"[Could not decode payload: {e}]"
    return "[No Payload]"


def process_packet(packet):
    """
    Callback function executed for every captured packet.
    Extracts and prints relevant fields in a readable format.
    """
    try:
        if packet.haslayer(IP):
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = get_protocol_name(packet)
            payload = safe_payload_preview(packet)

            print("-" * 70)
            print(f"[{timestamp}] {proto} Packet Captured")
            print(f"  Source IP      : {src_ip}")
            print(f"  Destination IP : {dst_ip}")

            # Show port info if available (helps in defense Q&A)
            if packet.haslayer(TCP):
                print(f"  Src Port       : {packet[TCP].sport}")
                print(f"  Dst Port       : {packet[TCP].dport}")
            elif packet.haslayer(UDP):
                print(f"  Src Port       : {packet[UDP].sport}")
                print(f"  Dst Port       : {packet[UDP].dport}")

            print(f"  Payload Preview: {payload}")
        else:
            # Non-IP packets (e.g., ARP) are skipped for simplicity
            pass

    except Exception as e:
        print(f"[!] Error processing packet: {e}")


def main():
    print("=" * 70)
    print(" Basic Network Sniffer — Educational Use Only")
    print(" Press Ctrl+C to stop capturing.")
    print("=" * 70)

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            count=PACKET_COUNT,
            store=False  # Don't keep packets in memory; print and discard
        )
    except PermissionError:
        print("[!] Permission denied. Run this script as Administrator (Windows) "
              "or with sudo (Linux/macOS).")
        sys.exit(1)
    except OSError as e:
        print(f"[!] OS-level error (check interface name / Npcap install): {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Sniffing stopped by user. Exiting cleanly.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()