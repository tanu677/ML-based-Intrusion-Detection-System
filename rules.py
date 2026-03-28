"""
firewall/rules.py
──────────────────
Firewall Rules Engine — evaluates flow features against
pre-defined ACL rules BEFORE the ML model sees the traffic.
Acts as a first-pass filter (Layer 4 firewall behaviour).
"""

from firewall.blocklist import is_blocked

# ── RULE DEFINITIONS ──────────────────────────────────────────────────────────
# Each rule: name, check function (receives flow dict), action, reason, severity
RULES = [

    # ── BLOCKLIST CHECK (always first) ────────────────────────────────────────
    {
        'name':     'Blocked IP check',
        'check':    lambda f: is_blocked(str(f.get('Src IP', ''))),
        'action':   'BLOCK',
        'reason':   'IP in blocklist',
        'severity': 'HIGH',
    },

    # ── KNOWN MALWARE PORTS ───────────────────────────────────────────────────
    {
        'name':     'Known malware port',
        'check':    lambda f: int(f.get('Dst Port', 0)) in [4444, 6667, 31337, 1337, 9999],
        'action':   'BLOCK',
        'reason':   'Known malware/C2 port',
        'severity': 'HIGH',
    },

    # ── SYN FLOOD ─────────────────────────────────────────────────────────────
    {
        'name':     'SYN Flood',
        'check':    lambda f: (
            float(f.get('SYN Flag Cnt', 0)) > 100 and
            float(f.get('ACK Flag Cnt', 0)) == 0
        ),
        'action':   'BLOCK',
        'reason':   'SYN Flood',
        'severity': 'HIGH',
    },

    # ── DDOS (extreme packet rate) ────────────────────────────────────────────
    {
        'name':     'DDoS packet rate',
        'check':    lambda f: float(f.get('Flow Pkts/s', 0)) > 10000,
        'action':   'BLOCK',
        'reason':   'DDoS - extreme packet rate',
        'severity': 'HIGH',
    },

    # ── RST ATTACK ────────────────────────────────────────────────────────────
    {
        'name':     'RST Attack',
        'check':    lambda f: float(f.get('RST Flag Cnt', 0)) > 50,
        'action':   'BLOCK',
        'reason':   'RST Attack',
        'severity': 'MEDIUM',
    },

    # ── BRUTE FORCE (many connections to SSH/FTP) ─────────────────────────────
    {
        'name':     'Brute Force',
        'check':    lambda f: (
            int(f.get('Dst Port', 0)) in [22, 21, 3389] and
            float(f.get('Tot Fwd Pkts', 0)) > 200
        ),
        'action':   'BLOCK',
        'reason':   'Brute Force attempt',
        'severity': 'MEDIUM',
    },

    # ── PORT SCAN ─────────────────────────────────────────────────────────────
    {
        'name':     'Port Scan',
        'check':    lambda f: (
            float(f.get('Flow Duration', 1)) < 100000 and
            float(f.get('Tot Fwd Pkts', 0)) <= 3 and
            float(f.get('Tot Bwd Pkts', 0)) == 0
        ),
        'action':   'BLOCK',
        'reason':   'Port Scan',
        'severity': 'MEDIUM',
    },

    # ── ALLOW STANDARD WEB ────────────────────────────────────────────────────
    {
        'name':     'Allow HTTP/HTTPS',
        'check':    lambda f: int(f.get('Dst Port', 0)) in [80, 443],
        'action':   'ALLOW',
        'reason':   'Standard web traffic',
        'severity': None,
    },

    # ── ALLOW DNS ─────────────────────────────────────────────────────────────
    {
        'name':     'Allow DNS',
        'check':    lambda f: int(f.get('Dst Port', 0)) == 53,
        'action':   'ALLOW',
        'reason':   'DNS traffic',
        'severity': None,
    },
]


def apply_rules(flow_row: dict) -> tuple:
    """
    Evaluate all rules against a flow row.
    Returns (action, reason, severity, rule_name)
    action = 'BLOCK' | 'ALLOW' | 'PASS_TO_IDS'
    """
    for rule in RULES:
        try:
            if rule['check'](flow_row):
                return (
                    rule['action'],
                    rule['reason'],
                    rule.get('severity'),
                    rule['name']
                )
        except Exception:
            continue

    # No rule matched — pass to IDS for ML analysis
    return ('PASS_TO_IDS', 'No firewall rule matched', None, 'Default')


def evaluate_batch(flows: list) -> list:
    """
    Evaluate a list of flow dicts.
    Returns list of result dicts with action added.
    """
    results = []
    for flow in flows:
        action, reason, severity, rule = apply_rules(flow)
        results.append({
            **flow,
            'fw_action':   action,
            'fw_reason':   reason,
            'fw_severity': severity,
            'fw_rule':     rule,
        })
    return results


if __name__ == '__main__':
    # Quick test flows
    test_flows = [
        {'Src IP': '10.0.0.1', 'Dst Port': 80,    'Flow Pkts/s': 100,   'SYN Flag Cnt': 0,   'ACK Flag Cnt': 5,  'RST Flag Cnt': 0,  'Tot Fwd Pkts': 10, 'Tot Bwd Pkts': 8,  'Flow Duration': 500000},
        {'Src IP': '10.0.0.2', 'Dst Port': 443,   'Flow Pkts/s': 200,   'SYN Flag Cnt': 0,   'ACK Flag Cnt': 10, 'RST Flag Cnt': 0,  'Tot Fwd Pkts': 20, 'Tot Bwd Pkts': 15, 'Flow Duration': 300000},
        {'Src IP': '10.0.0.3', 'Dst Port': 8080,  'Flow Pkts/s': 50000, 'SYN Flag Cnt': 0,   'ACK Flag Cnt': 0,  'RST Flag Cnt': 0,  'Tot Fwd Pkts': 500,'Tot Bwd Pkts': 0,  'Flow Duration': 10000},
        {'Src IP': '10.0.0.4', 'Dst Port': 8080,  'Flow Pkts/s': 10,    'SYN Flag Cnt': 500, 'ACK Flag Cnt': 0,  'RST Flag Cnt': 0,  'Tot Fwd Pkts': 500,'Tot Bwd Pkts': 0,  'Flow Duration': 200000},
        {'Src IP': '10.0.0.5', 'Dst Port': 22,    'Flow Pkts/s': 30,    'SYN Flag Cnt': 5,   'ACK Flag Cnt': 5,  'RST Flag Cnt': 0,  'Tot Fwd Pkts': 300,'Tot Bwd Pkts': 100,'Flow Duration': 900000},
        {'Src IP': '10.0.0.6', 'Dst Port': 4444,  'Flow Pkts/s': 10,    'SYN Flag Cnt': 1,   'ACK Flag Cnt': 1,  'RST Flag Cnt': 0,  'Tot Fwd Pkts': 5,  'Tot Bwd Pkts': 3,  'Flow Duration': 200000},
    ]

    print(f'\n{"─"*70}')
    print(f'  {"SRC IP":<16} {"DST PORT":<10} {"ACTION":<14} {"REASON"}')
    print(f'{"─"*70}')
    for flow in test_flows:
        action, reason, severity, rule = apply_rules(flow)
        print(f'  {str(flow["Src IP"]):<16} {str(flow["Dst Port"]):<10} {action:<14} {reason}')
    print(f'{"─"*70}\n')
