"""
simulation/run_simulation.py
──────────────────────────────
Main pipeline runner.

TWO MODES:
  Mode A — Live: loads CICFlowMeter CSV output from your PCAP capture
  Mode B — Demo: generates synthetic flow rows without needing Scapy/Wireshark
            (useful for testing the IDS pipeline quickly)

Usage:
  python simulation/run_simulation.py --mode demo
  python simulation/run_simulation.py --mode live --file path/to/cicflow_output.csv
"""

import argparse
import sys
import os
import numpy as np
import pandas as pd
import joblib

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from firewall.rules    import apply_rules
from firewall.response import handle_alert, show_alert_summary
from firewall.blocklist import clear_blocklist, show_blocklist

# ── PATHS ─────────────────────────────────────────────────────────────────────
MODEL_PATH  = os.path.join(os.path.dirname(__file__), '..', 'models', 'isolation_forest.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'scaler.pkl')

# ── FEATURES (must match your trained model) ──────────────────────────────────
FEATURES = [
    'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
    'Flow Byts/s', 'Flow Pkts/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len',
    'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
    'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
    'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
    'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
    'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts',
    'Fwd Act Data Pkts', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Protocol', 'Dst Port'
]


# ── LOAD MODEL ────────────────────────────────────────────────────────────────
def load_model():
    if not os.path.exists(MODEL_PATH):
        print(f'ERROR: Model not found at {MODEL_PATH}')
        print('Run your notebook first to train and save the model.')
        sys.exit(1)
    if not os.path.exists(SCALER_PATH):
        print(f'ERROR: Scaler not found at {SCALER_PATH}')
        sys.exit(1)

    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f'[MODEL] Isolation Forest loaded — {model.n_estimators} estimators')
    return model, scaler


# ── PREPROCESS FLOW ───────────────────────────────────────────────────────────
def preprocess(df: pd.DataFrame, scaler) -> np.ndarray:
    """Clean and scale a flow DataFrame for the model."""
    # Keep only known features, fill missing with 0
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0.0

    X = df[FEATURES].copy()
    X = X.apply(pd.to_numeric, errors='coerce')
    X.replace([float('inf'), float('-inf')], float('nan'), inplace=True)
    X.fillna(0, inplace=True)

    # ── Feature engineering (must match notebook exactly) ──
    if 'Tot Fwd Pkts' in X.columns and 'Tot Bwd Pkts' in X.columns:
        X['Fwd_Bwd_Pkt_Ratio'] = X['Tot Fwd Pkts'] / (X['Tot Bwd Pkts'] + 1)

    if 'Flow Byts/s' in X.columns and 'Flow Pkts/s' in X.columns:
        X['Bytes_Per_Pkt'] = X['Flow Byts/s'] / (X['Flow Pkts/s'] + 1)

    flag_cols = [c for c in ['SYN Flag Cnt', 'ACK Flag Cnt', 'RST Flag Cnt',
            'FIN Flag Cnt', 'PSH Flag Cnt', 'URG Flag Cnt']
                if c in X.columns]
    if flag_cols and 'Tot Fwd Pkts' in X.columns:
        X['Flag_Density'] = X[flag_cols].sum(axis=1) / (X['Tot Fwd Pkts'] + 1)

    # Use all columns the scaler expects
    scaler_features = scaler.feature_names_in_
    for col in scaler_features:
        if col not in X.columns:
            X[col] = 0.0

    return scaler.transform(X[scaler_features])

# ── RULE ENGINE ───────────────────────────────────────────────────────────────
def rule_engine(row: dict) -> str:
    """Classify a flow using data-driven rules. Returns attack type or 'Normal'."""
    if row.get('SYN Flag Cnt', 0) > 50 and row.get('ACK Flag Cnt', 0) == 0:
        return 'SYN Flood'
    if row.get('Flow Pkts/s', 0) > 10000:
        return 'DDoS'
    if row.get('RST Flag Cnt', 0) > 30:
        return 'RST Attack'
    if row.get('Dst Port', 0) in [22, 21] and row.get('Tot Fwd Pkts', 0) > 150:
        return 'Brute Force'
    if row.get('Flow Byts/s', 0) > 5000000:
        return 'High Volume'
    return 'Normal'


# ── HYBRID DETECTION ──────────────────────────────────────────────────────────
def detect(df: pd.DataFrame, model, scaler) -> pd.DataFrame:
    """
    Full hybrid detection pipeline:
    1. Firewall rules (pre-filter)
    2. Isolation Forest (ML anomaly detection)
    3. Rule engine (confirmation)
    4. Hybrid decision
    """
    results = df.copy()
    results['Src IP'] = results.get('Src IP', pd.Series(['10.0.0.1'] * len(df)))

    # Step 1 — Firewall pre-filter
    fw_actions = []
    for _, row in results.iterrows():
        action, reason, severity, rule = apply_rules(row.to_dict())
        fw_actions.append({'fw_action': action, 'fw_reason': reason})
    fw_df = pd.DataFrame(fw_actions, index=results.index)
    results = pd.concat([results, fw_df], axis=1)

    # Step 2 — ML: Isolation Forest on rows not already blocked
    pass_to_ids = results[results['fw_action'] != 'BLOCK'].copy()
    X_scaled = preprocess(pass_to_ids.copy(), scaler)
    iso_raw  = model.predict(X_scaled)
    iso_pred = np.where(iso_raw == -1, 1, 0)
    iso_scores = -model.score_samples(X_scaled)

    pass_to_ids = pass_to_ids.copy()
    pass_to_ids['iso_pred']   = iso_pred
    pass_to_ids['iso_score']  = iso_scores

    # Step 3 — Rule engine
    pass_to_ids['rule_result'] = pass_to_ids.apply(
        lambda r: rule_engine(r.to_dict()), axis=1
    )

    # Step 4 — Hybrid decision
    def hybrid(row):
        if row['iso_pred'] == 1:
            return row['rule_result'] if row['rule_result'] != 'Normal' else 'Attack'
        if row['rule_result'] != 'Normal':
            return row['rule_result']
        return 'Normal'

    pass_to_ids['Final_Result'] = pass_to_ids.apply(hybrid, axis=1)
    pass_to_ids['Confidence']   = pass_to_ids['iso_score'] / (pass_to_ids['iso_score'].max() + 1e-9)

    # Merge back — firewall-blocked rows are 'Attack'
    results.loc[results['fw_action'] == 'BLOCK', 'Final_Result'] = 'Firewall Block'
    results.loc[results['fw_action'] == 'BLOCK', 'Confidence']   = 1.0
    results.update(pass_to_ids[['Final_Result', 'Confidence', 'iso_pred', 'rule_result']])

    return results


# ── DEMO MODE: synthetic flows ─────────────────────────────────────────────────
def generate_demo_flows() -> pd.DataFrame:
    """
    Creates synthetic flow rows representing each attack type + benign.
    No Scapy required — useful for quick testing.
    """
    import random

    flows = []

    # Benign flows
    for _ in range(20):
        flows.append({
            'Src IP': f'192.168.1.{random.randint(2,50)}',
            'Dst Port': random.choice([80, 443]),
            'Flow Duration': random.randint(100000, 900000),
            'Tot Fwd Pkts': random.randint(5, 30),
            'Tot Bwd Pkts': random.randint(3, 20),
            'Flow Byts/s': random.uniform(500, 5000),
            'Flow Pkts/s': random.uniform(10, 200),
            'SYN Flag Cnt': random.randint(0, 2),
            'ACK Flag Cnt': random.randint(1, 10),
            'RST Flag Cnt': 0,
            'FIN Flag Cnt': random.randint(0, 2),
            'PSH Flag Cnt': random.randint(0, 5),
            'URG Flag Cnt': 0,
            'True_Label': 'BENIGN'
        })

    # SYN Flood
    for _ in range(10):
        flows.append({
            'Src IP': '10.0.0.99',
            'Dst Port': 80,
            'Flow Duration': random.randint(10000, 50000),
            'Tot Fwd Pkts': random.randint(200, 600),
            'Tot Bwd Pkts': 0,
            'Flow Byts/s': random.uniform(50000, 200000),
            'Flow Pkts/s': random.uniform(1000, 5000),
            'SYN Flag Cnt': random.randint(150, 500),
            'ACK Flag Cnt': 0,
            'RST Flag Cnt': 0,
            'FIN Flag Cnt': 0,
            'PSH Flag Cnt': 0,
            'URG Flag Cnt': 0,
            'True_Label': 'SYN Flood'
        })

    # DDoS
    for _ in range(10):
        flows.append({
            'Src IP': '172.16.0.55',
            'Dst Port': 53,
            'Flow Duration': random.randint(1000, 10000),
            'Tot Fwd Pkts': random.randint(500, 2000),
            'Tot Bwd Pkts': 0,
            'Flow Byts/s': random.uniform(500000, 2000000),
            'Flow Pkts/s': random.uniform(15000, 50000),
            'SYN Flag Cnt': 0,
            'ACK Flag Cnt': 0,
            'RST Flag Cnt': 0,
            'FIN Flag Cnt': 0,
            'PSH Flag Cnt': 0,
            'URG Flag Cnt': 0,
            'True_Label': 'DDoS'
        })

    # RST Attack
    for _ in range(8):
        flows.append({
            'Src IP': '10.10.0.33',
            'Dst Port': 443,
            'Flow Duration': random.randint(5000, 30000),
            'Tot Fwd Pkts': random.randint(100, 300),
            'Tot Bwd Pkts': 0,
            'Flow Byts/s': random.uniform(10000, 80000),
            'Flow Pkts/s': random.uniform(500, 2000),
            'SYN Flag Cnt': 0,
            'ACK Flag Cnt': 0,
            'RST Flag Cnt': random.randint(80, 200),
            'FIN Flag Cnt': 0,
            'PSH Flag Cnt': 0,
            'URG Flag Cnt': 0,
            'True_Label': 'RST Attack'
        })

    # Brute Force SSH
    for _ in range(8):
        flows.append({
            'Src IP': '192.168.99.1',
            'Dst Port': 22,
            'Flow Duration': random.randint(500000, 2000000),
            'Tot Fwd Pkts': random.randint(200, 500),
            'Tot Bwd Pkts': random.randint(50, 150),
            'Flow Byts/s': random.uniform(1000, 10000),
            'Flow Pkts/s': random.uniform(50, 300),
            'SYN Flag Cnt': random.randint(50, 150),
            'ACK Flag Cnt': random.randint(50, 150),
            'RST Flag Cnt': random.randint(20, 80),
            'FIN Flag Cnt': 0,
            'PSH Flag Cnt': random.randint(5, 20),
            'URG Flag Cnt': 0,
            'True_Label': 'Brute Force'
        })

    df = pd.DataFrame(flows)

    # Fill all missing FEATURES columns with 0
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0.0

    return df


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Hybrid IDS Simulation Runner')
    parser.add_argument('--mode', choices=['demo', 'live'], default='demo',
                        help='demo = synthetic flows | live = CICFlowMeter CSV')
    parser.add_argument('--file', default=None,
                        help='Path to CICFlowMeter CSV (required for live mode)')
    parser.add_argument('--clear', action='store_true',
                        help='Clear blocklist before running')
    args = parser.parse_args()

    print('\n' + '='*60)
    print('  HYBRID IDS — SIMULATION PIPELINE')
    print('='*60)

    # Optional: clear old blocklist
    if args.clear:
        clear_blocklist()

    # Load trained model
    model, scaler = load_model()

    # Load flows
    if args.mode == 'demo':
        print('\n[MODE] Demo — using synthetic generated flows')
        df = generate_demo_flows()
        print(f'[DATA] {len(df)} synthetic flows generated')
        print(f'       Attack types: {df["True_Label"].value_counts().to_dict()}')

    elif args.mode == 'live':
        if not args.file:
            print('ERROR: --file required for live mode')
            sys.exit(1)
        print(f'\n[MODE] Live — loading CICFlowMeter output: {args.file}')
        df = pd.read_csv(args.file, low_memory=False)
        df.columns = df.columns.str.strip()
        print(f'[DATA] {len(df):,} flows loaded from CSV')

    # Run detection
    print('\n[DETECTION] Running hybrid pipeline...')
    results = detect(df, model, scaler)

    # Print results summary
    print(f'\n{"="*60}')
    print('  DETECTION RESULTS')
    print(f'{"="*60}')
    print(results['Final_Result'].value_counts().to_string())
    print(f'{"="*60}\n')

    # Handle alerts — call firewall response for each attack
    attacks = results[results['Final_Result'] != 'Normal']
    print(f'[RESPONSE] {len(attacks)} attacks detected — triggering firewall response...\n')

    for _, row in attacks.iterrows():
        handle_alert(
            src_ip      = str(row.get('Src IP', '0.0.0.0')),
            dst_port    = int(row.get('Dst Port', 0)),
            attack_type = str(row.get('Final_Result', 'Unknown')),
            confidence  = float(row.get('Confidence', 0.5)),
        )

    # Final summary
    show_alert_summary()
    show_blocklist()

    # Save full results
    os.makedirs('logs', exist_ok=True)
    results.to_csv('logs/simulation_results.csv', index=False)
    print('[OUTPUT] Full results saved to logs/simulation_results.csv')


if __name__ == '__main__':
    main()
