"""
firewall/response.py
─────────────────────
Response Action Handler — called when hybrid IDS confirms an attack.

1. Logs the alert to CSV
2. Pushes block rule to JSON blocklist
3. ACTUALLY blocks the IP in Windows Firewall via netsh subprocess
4. Can also remove rules (unblock)

IMPORTANT: Must run Python / Jupyter as Administrator for
           Windows Firewall integration to work.
"""

import os
import subprocess
import platform
import pandas as pd
from datetime import datetime
from firewall.blocklist import block_ip, show_blocklist

ALERTS_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'alerts.csv')
IS_WINDOWS  = platform.system() == 'Windows'


# ── CHECK ADMIN RIGHTS ────────────────────────────────────────────────────────
def _check_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

IS_ADMIN = _check_admin()

if not IS_ADMIN:
    print('[FIREWALL] WARNING: Not running as Administrator.')
    print('           Windows Firewall rules will NOT be applied.')
    print('           Restart Python/Jupyter as Administrator to enable.\n')
else:
    print('[FIREWALL] Admin rights confirmed — Windows Firewall integration active.')


# ── SEVERITY MAP ──────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    'DDOS':         'HIGH',
    'SYN FLOOD':    'HIGH',
    'RST ATTACK':   'HIGH',
    'BRUTEFORCE':   'MEDIUM',
    'BRUTE FORCE':  'MEDIUM',
    'PORT SCAN':    'MEDIUM',
    'HIGH VOLUME':  'MEDIUM',
    'INJECTION':    'HIGH',
    'BOT':          'HIGH',
    'INFILTRATION': 'HIGH',
    'UNKNOWN':      'LOW',
}

def get_severity(attack_type: str) -> str:
    return SEVERITY_MAP.get(attack_type.upper().strip(), 'LOW')


# ── WINDOWS FIREWALL FUNCTIONS ────────────────────────────────────────────────

def _rule_exists(ip: str) -> bool:
    """Check if a block rule already exists for this IP in Windows Firewall."""
    if not IS_WINDOWS:
        return False
    try:
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
             f'name=IDS_Block_{ip}'],
            capture_output=True, text=True
        )
        return 'No rules match' not in result.stdout
    except Exception:
        return False


def windows_block_ip(ip: str, attack_type: str) -> bool:
    """
    Adds a REAL inbound block rule to Windows Firewall.

    Runs this command via subprocess:
      netsh advfirewall firewall add rule
            name="IDS_Block_<ip>"
            dir=in
            action=block
            remoteip=<ip>
            enable=yes
            profile=any

    Returns True if rule was applied successfully.
    """
    if not IS_WINDOWS:
        print(f'[FIREWALL] Non-Windows system — skipping netsh')
        return False

    if not IS_ADMIN:
        print(f'[FIREWALL] Not Admin — cannot apply Windows Firewall rule for {ip}')
        print(f'[FIREWALL] Manual command:')
        print(f'  netsh advfirewall firewall add rule name="IDS_Block_{ip}" '
              f'dir=in action=block remoteip={ip}')
        return False

    if _rule_exists(ip):
        print(f'[FIREWALL] Rule already exists for {ip} — skipping duplicate')
        return True

    cmd = [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name=IDS_Block_{ip}',
        'dir=in',
        'action=block',
        f'remoteip={ip}',
        f'description=Blocked by Hybrid IDS: {attack_type}',
        'enable=yes',
        'profile=any',
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f'[FIREWALL] Rule applied — {ip} is now BLOCKED in Windows Firewall')
            print(f'           Verify: Windows Defender Firewall → Inbound Rules → IDS_Block_{ip}')
            return True
        else:
            print(f'[FIREWALL] netsh failed for {ip}')
            print(f'           Error: {result.stderr.strip()}')
            return False

    except FileNotFoundError:
        print('[FIREWALL] netsh not found')
        return False
    except Exception as e:
        print(f'[FIREWALL] Unexpected error: {e}')
        return False


def windows_unblock_ip(ip: str) -> bool:
    """
    Removes the Windows Firewall block rule for the given IP.
    Call this to unblock a previously blocked IP.
    """
    if not IS_WINDOWS or not IS_ADMIN:
        print(f'[FIREWALL] Must be Windows Admin to unblock IPs')
        return False

    cmd = [
        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
        f'name=IDS_Block_{ip}',
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'[FIREWALL] Rule removed — {ip} is UNBLOCKED')
            return True
        else:
            print(f'[FIREWALL] Could not remove rule for {ip}: {result.stderr.strip()}')
            return False
    except Exception as e:
        print(f'[FIREWALL] Error: {e}')
        return False


def windows_list_ids_rules():
    """Show all active IDS block rules in Windows Firewall."""
    if not IS_WINDOWS:
        print('[FIREWALL] Not a Windows system.')
        return

    try:
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
            capture_output=True, text=True
        )
        lines   = result.stdout.split('\n')
        rules   = []
        current = {}

        for line in lines:
            if 'IDS_Block_' in line and line.startswith('Rule Name:'):
                current = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('RemoteIP:') and current:
                current['ip'] = line.split(':', 1)[1].strip()
                rules.append(current)
                current = {}

        if rules:
            print(f'\n[FIREWALL] {len(rules)} active IDS block rules:')
            print(f'  {"RULE NAME":<30} IP')
            print(f'  {"─"*50}')
            for r in rules:
                print(f'  {r.get("name",""):<30} {r.get("ip","")}')
        else:
            print('[FIREWALL] No IDS block rules currently active.')

    except Exception as e:
        print(f'[FIREWALL] Error listing rules: {e}')


def windows_clear_all_ids_rules():
    """
    Remove ALL IDS block rules from Windows Firewall.
    Useful for resetting after a test run.
    """
    if not IS_WINDOWS or not IS_ADMIN:
        print('[FIREWALL] Must be Windows Admin.')
        return

    try:
        # Get all rule names first
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
            capture_output=True, text=True
        )
        lines = result.stdout.split('\n')
        ids_rules = [
            line.split(':', 1)[1].strip()
            for line in lines
            if 'IDS_Block_' in line and line.startswith('Rule Name:')
        ]

        if not ids_rules:
            print('[FIREWALL] No IDS rules to clear.')
            return

        removed = 0
        for rule_name in ids_rules:
            del_result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}'],
                capture_output=True, text=True
            )
            if del_result.returncode == 0:
                removed += 1

        print(f'[FIREWALL] Cleared {removed} IDS block rules from Windows Firewall.')

    except Exception as e:
        print(f'[FIREWALL] Error clearing rules: {e}')


# ── MAIN ALERT HANDLER ────────────────────────────────────────────────────────

def handle_alert(
    src_ip:      str,
    dst_port:    int,
    attack_type: str,
    confidence:  float,
    flow_row:    dict = None
):
    """
    Full response pipeline for one confirmed attack:
    1. Print alert
    2. Log to CSV
    3. Update JSON blocklist
    4. Block IP in Windows Firewall (real netsh call)
    """
    severity  = get_severity(attack_type)
    timestamp = datetime.now().isoformat()

    # 1 — Print alert
    print(f'\n{"═"*62}')
    print(f'  [ALERT] {severity} — {attack_type.upper()}')
    print(f'{"═"*62}')
    print(f'  Timestamp   : {timestamp}')
    print(f'  Source IP   : {src_ip}')
    print(f'  Dst Port    : {dst_port}')
    print(f'  Attack Type : {attack_type}')
    print(f'  Confidence  : {confidence:.2%}')
    print(f'  Severity    : {severity}')

    # 2 — Log to CSV
    _log_alert(timestamp, src_ip, dst_port, attack_type, severity, confidence)

    # 3 — JSON blocklist
    block_ip(src_ip, reason=attack_type, severity=severity)

    # 4 — Windows Firewall REAL block
    print(f'\n  [WINDOWS FIREWALL] Blocking {src_ip}...')
    windows_block_ip(src_ip, attack_type)
    print(f'{"═"*62}\n')


def handle_batch_alerts(results_df: pd.DataFrame):
    """Handle all attacks in a DataFrame."""
    attacks = results_df[results_df['Final_Result'] != 'Normal']
    if len(attacks) == 0:
        print('[RESPONSE] No attacks detected.')
        return

    print(f'\n[RESPONSE] {len(attacks):,} attacks — applying firewall blocks...')
    for _, row in attacks.iterrows():
        handle_alert(
            src_ip      = str(row.get('Src IP', '0.0.0.0')),
            dst_port    = int(row.get('Dst Port', 0)),
            attack_type = str(row.get('Final_Result', 'UNKNOWN')),
            confidence  = float(row.get('Confidence', 0.8)),
        )

    print(f'\n[RESPONSE] Done. {len(attacks):,} IPs blocked.')
    show_blocklist()
    windows_list_ids_rules()


# ── LOGGING ───────────────────────────────────────────────────────────────────

def _log_alert(timestamp, src_ip, dst_port, attack_type, severity, confidence):
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    alert = pd.DataFrame([{
        'timestamp':    timestamp,
        'src_ip':       src_ip,
        'dst_port':     dst_port,
        'attack_type':  attack_type,
        'severity':     severity,
        'confidence':   round(confidence, 4),
        'fw_blocked':   IS_WINDOWS and IS_ADMIN,
        'action':       'BLOCKED',
    }])
    alert.to_csv(
        ALERTS_FILE,
        mode='a',
        header=not os.path.exists(ALERTS_FILE),
        index=False
    )


def show_alert_summary():
    if not os.path.exists(ALERTS_FILE):
        print('[RESPONSE] No alerts logged yet.')
        return
    df = pd.read_csv(ALERTS_FILE)
    print(f'\n{"═"*55}')
    print(f'  ALERT SUMMARY — {len(df)} total alerts')
    print(f'{"═"*55}')
    print(df.groupby(['attack_type', 'severity'])['src_ip']
            .count().rename('count').reset_index().to_string(index=False))
    print(f'{"═"*55}\n')


# ── QUICK TEST ────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f'Platform : {platform.system()}')
    print(f'Admin    : {IS_ADMIN}\n')

    handle_alert('192.168.1.100', 80,  'SYN Flood', 0.94)
    handle_alert('10.0.0.55',     443, 'DDoS',       0.87)
    handle_alert('172.16.0.22',   22,  'Brute Force',0.76)

    show_alert_summary()
    windows_list_ids_rules()
