"""
firewall/blocklist.py
─────────────────────
IP Blocklist Manager — persists blocked IPs to JSON.
Called by response.py whenever the IDS confirms an attack.
"""

import json
import os
from datetime import datetime

BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'blocklist.json')


def _load() -> dict:
    """Load blocklist from disk. Returns empty dict if file doesn't exist."""
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'r') as f:
            return json.load(f)
    return {}


def _save(blocklist: dict):
    """Persist blocklist to disk."""
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    with open(BLOCKLIST_FILE, 'w') as f:
        json.dump(blocklist, f, indent=2)


def block_ip(ip: str, reason: str, severity: str):
    """
    Add an IP to the blocklist.
    If already blocked, updates the entry with latest reason.
    """
    blocklist = _load()

    blocklist[ip] = {
        'reason':     reason,
        'severity':   severity,
        'blocked_at': datetime.now().isoformat(),
        'count':      blocklist.get(ip, {}).get('count', 0) + 1
    }

    _save(blocklist)

    print(f'[FIREWALL] ✖ BLOCKED  {ip:<18} | {severity:<6} | {reason}')


def unblock_ip(ip: str):
    """Remove an IP from the blocklist."""
    blocklist = _load()
    if ip in blocklist:
        del blocklist[ip]
        _save(blocklist)
        print(f'[FIREWALL] ✔ UNBLOCKED {ip}')
    else:
        print(f'[FIREWALL] {ip} not in blocklist')


def is_blocked(ip: str) -> bool:
    """Return True if IP is currently blocked."""
    return ip in _load()


def show_blocklist():
    """Print all currently blocked IPs."""
    blocklist = _load()
    if not blocklist:
        print('[FIREWALL] Blocklist is empty.')
        return
    print(f'\n{"─"*65}')
    print(f'  {"IP ADDRESS":<18} {"SEVERITY":<8} {"REASON":<20} {"BLOCKED AT"}')
    print(f'{"─"*65}')
    for ip, info in blocklist.items():
        print(f'  {ip:<18} {info["severity"]:<8} {info["reason"]:<20} {info["blocked_at"][:19]}')
    print(f'{"─"*65}')
    print(f'  Total blocked IPs: {len(blocklist)}\n')


def clear_blocklist():
    """Wipe the entire blocklist (use for testing)."""
    _save({})
    print('[FIREWALL] Blocklist cleared.')


if __name__ == '__main__':
    # Quick test
    block_ip('192.168.1.100', 'SYN Flood',   'HIGH')
    block_ip('10.0.0.55',     'DDoS',         'HIGH')
    block_ip('172.16.0.22',   'Brute Force',  'MEDIUM')
    show_blocklist()
    print('Is 10.0.0.55 blocked?', is_blocked('10.0.0.55'))
    print('Is 8.8.8.8 blocked?',   is_blocked('8.8.8.8'))
