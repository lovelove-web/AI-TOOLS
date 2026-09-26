"""
Network IDS Lab Monitor — SQLite-backed version
    I have tried without pickle but I got so many error that is why I brought pickle again.
"""

import os
import sys
import time
import math
import json
import sqlite3
import pickle
import argparse
import warnings
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

INTERFACE = r"\Device\NPF_{19B8D6CC-2212-44B4-B0BB-3090629EB758}"
LAB_IP = "192.168.40.129"
KALI_IP = "192.168.40.130"
LAB_NETWORK = "192.168.40.0/24"
DB_FILE = "nids_lab.db"

FEATURE_NAMES = [
    "avg_ipt", "bytes_in", "bytes_out", "dest_ip", "dest_port",
    "duration", "entropy", "num_pkts_in", "num_pkts_out", "proto",
    "src_ip", "src_port", "time_end", "time_start", "total_entropy"
]


# --------------------------------------------------------------------- SQLite

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""CREATE TABLE IF NOT EXISTS models (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT NOT NULL,
        accuracy REAL,
        feature_names TEXT NOT NULL,
        model_blob BLOB NOT NULL,
        scaler_blob BLOB NOT NULL,
        created_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        src_ip TEXT, src_port INTEGER,
        dst_ip TEXT, dst_port INTEGER,
        proto INTEGER,
        prediction TEXT,
        confidence REAL
    )""")
    conn.commit()
    return conn


def migrate_pickle_to_db(pkl_path):
    """One-time import of an existing nids_moodel.pkl into the SQLite database."""
    if not os.path.exists(pkl_path):
        raise FileNotFoundError(pkl_path)

    with open(pkl_path, "rb") as f:
        bundle = pickle.load(f)

    stored = list(bundle.get("feature_names", []))
    if stored != FEATURE_NAMES:
        raise ValueError(
            f"'{pkl_path}' feature schema does not match expected schema.\n"
            f"Stored: {stored}\nExpected: {FEATURE_NAMES}"
        )

    conn = get_connection()
    conn.execute("UPDATE models SET is_active = 0")
    conn.execute(
        "INSERT INTO models (model_name, accuracy, feature_names, model_blob, "
        "scaler_blob, created_at, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)",
        (
            bundle.get("model_name", type(bundle["model"]).__name__),
            bundle.get("accuracy"),
            json.dumps(FEATURE_NAMES),
            pickle.dumps(bundle["model"]),
            pickle.dumps(bundle["scaler"]),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    print(f"[+] Imported '{pkl_path}' into {DB_FILE}")


def log_alert_to_db(conn, f, pred, prob):
    conn.execute(
        "INSERT INTO alerts (ts, src_ip, src_port, dst_ip, dst_port, proto, "
        "prediction, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now().isoformat(),
            f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["proto"],
            str(pred), prob,
        ),
    )
    conn.commit()


# ---------------------------------------------------------------- feature math

def ip_number(ip):
    try:
        a, b, c, d = map(int, str(ip).split("."))
        return float((a << 24) | (b << 16) | (c << 8) | d)
    except Exception:
        return 0.0


def packet_size(p):
    try:
        if IP in p and p[IP].len is not None:
            return max(0, int(p[IP].len))
    except Exception:
        pass
    try:
        return len(bytes(p[Raw])) if Raw in p else 0
    except Exception:
        return 0


def get_ports(p):
    if TCP in p:
        return int(p[TCP].sport), int(p[TCP].dport)
    if UDP in p:
        return int(p[UDP].sport), int(p[UDP].dport)
    return 0, 0


def entropy(values):
    if not values:
        return 0.0
    counts = defaultdict(int)
    for x in values:
        counts[max(1, int(x))] += 1
    n = float(len(values))
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def is_attack(pred):
    return str(pred).strip().lower() not in {
        "0", "normal", "benign", "safe", "normal traffic"
    }


# --------------------------------------------------------------------- engine

class LabNIDS:
    def __init__(self):
        self.flows = {}
        self.total_packets = self.predictions = self.alerts = self.errors = 0
        self.started = time.time()
        self.db = get_connection()
        self.load_model()

    def load_model(self):
        print("[*] Loading trained model from database...")
        print(f"[*] Database file: {DB_FILE}")

        row = self.db.execute(
            "SELECT model_name, accuracy, feature_names, model_blob, scaler_blob "
            "FROM models WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()

        if row is None:
            raise RuntimeError(
                f"No active model found in {DB_FILE}. Run once with "
                f"--migrate <path_to_nids_moodel.pkl> to import it."
            )

        model_name, accuracy, feature_names_json, model_blob, scaler_blob = row
        stored = json.loads(feature_names_json)
        if stored != FEATURE_NAMES:
            raise ValueError(
                "Stored model features do not match expected schema.\n"
                f"Stored: {stored}\nExpected: {FEATURE_NAMES}"
            )

        self.model = pickle.loads(model_blob)
        self.scaler = pickle.loads(scaler_blob)
        self.model_name = model_name
        self.accuracy = accuracy

        print(f"[+] Model loaded: {self.model_name}")
        if self.accuracy is not None:
            try:
                print(f"[+] Training accuracy: {float(self.accuracy) * 100:.2f}%")
            except Exception:
                print(f"[+] Training accuracy: {self.accuracy}")
        print(f"[+] Feature schema ({len(FEATURE_NAMES)}): " + ", ".join(FEATURE_NAMES))

    def key(self, p):
        if IP not in p:
            return None
        sp, dp = get_ports(p)
        return (p[IP].src, sp, p[IP].dst, dp, int(p[IP].proto))

    def update_flow(self, p, ts):
        k = self.key(p)
        if k is None:
            return None
        if k not in self.flows:
            src, sp, dst, dp, proto = k
            self.flows[k] = {
                "src_ip": src, "src_port": sp, "dst_ip": dst, "dst_port": dp,
                "proto": proto, "start": ts, "last": ts,
                "bytes_in": 0, "bytes_out": 0,
                "num_pkts_in": 0, "num_pkts_out": 0,
                "times": [], "sizes": []
            }
        f = self.flows[k]
        size = packet_size(p)
        f["last"] = ts
        f["times"].append(ts)
        f["sizes"].append(size)
        if p[IP].src == f["src_ip"]:
            f["bytes_out"] += size
            f["num_pkts_out"] += 1
        else:
            f["bytes_in"] += size
            f["num_pkts_in"] += 1
        if len(f["times"]) > 500:
            f["times"] = f["times"][-500:]
            f["sizes"] = f["sizes"][-500:]
        return f

    def make_features(self, f):
        intervals = [
            f["times"][i] - f["times"][i - 1]
            for i in range(1, len(f["times"]))
        ]
        avg = sum(intervals) / len(intervals) if intervals else 0.0
        e = entropy(f["sizes"])
        return {
            "avg_ipt": float(avg),
            "bytes_in": float(f["bytes_in"]),
            "bytes_out": float(f["bytes_out"]),
            "dest_ip": ip_number(f["dst_ip"]),
            "dest_port": float(f["dst_port"]),
            "duration": float(max(0, f["last"] - f["start"])),
            "entropy": e,
            "num_pkts_in": float(f["num_pkts_in"]),
            "num_pkts_out": float(f["num_pkts_out"]),
            "proto": float(f["proto"]),
            "src_ip": ip_number(f["src_ip"]),
            "src_port": float(f["src_port"]),
            "time_end": float(f["last"]),
            "time_start": float(f["start"]),
            "total_entropy": e
        }

    def predict(self, f):
        x = self.make_features(f)
        df = pd.DataFrame([[x[n] for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
        scaled = self.scaler.transform(df)
        pred = self.model.predict(scaled)[0]
        prob = None
        if hasattr(self.model, "predict_proba"):
            try:
                prob = float(np.max(self.model.predict_proba(scaled)[0]))
            except Exception:
                pass
        return pred, prob

    def callback(self, p):
        if IP not in p or (p[IP].src != LAB_IP and p[IP].dst != LAB_IP):
            return

        self.total_packets += 1
        ts = float(getattr(p, "time", time.time()))
        f = self.update_flow(p, ts)
        if f is None:
            return

        count = f["num_pkts_in"] + f["num_pkts_out"]
        if count not in {1, 2, 3, 5, 10, 20, 50} and count % 100 != 0:
            return

        try:
            pred, prob = self.predict(f)
            self.predictions += 1
            attack = is_attack(pred)
            status = "ALERT" if attack else "NORMAL"
            conf = f"{prob * 100:.1f}%" if prob is not None else "N/A"

            if TCP in p:
                desc = f"TCP {f['src_port']}->{f['dst_port']} flags={p[TCP].flags}"
            elif UDP in p:
                desc = f"UDP {f['src_port']}->{f['dst_port']}"
            elif ICMP in p:
                desc = "ICMP"
            else:
                desc = f"IP proto {f['proto']}"

            print(
                f"{datetime.fromtimestamp(ts).strftime('%H:%M:%S'):>8} | "
                f"{status:^6} | {f['src_ip']:<15} -> {f['dst_ip']:<15} | "
                f"{desc:<42.42} | confidence={conf:>6}"
            )

            if attack:
                self.alerts += 1
                log_alert_to_db(self.db, f, pred, prob)
                print("         [!] Alert recorded in database")

        except Exception as e:
            self.errors += 1
            print(f"[WARNING] ML prediction error: {e}")

    def run(self):
        print("\n" + "=" * 80)
        print(" NETWORK INTRUSION DETECTION SYSTEM — VMware Isolated Lab")
        print("=" * 80)
        print(f"[*] Capture interface : {INTERFACE}")
        print(f"[*] Windows lab IP    : {LAB_IP}")
        print(f"[*] Kali lab IP       : {KALI_IP}")
        print(f"[*] Network           : {LAB_NETWORK}")
        print("\n[*] Starting network monitoring...")
        print("[*] Waiting for Kali traffic...")
        print("[*] Press CTRL+C to stop and show the summary.\n")
        print("=" * 100)
        print(f"{'Time':>8} | {'Status':^6} | {'Source':<15} -> {'Destination':<15} | "
              f"{'Description':<42} | {'Confidence':>10}")
        print("=" * 100)

        try:
            sniff(iface=INTERFACE, prn=self.callback, store=False)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
        finally:
            print("\n" + "=" * 80)
            print(" NIDS LAB SUMMARY")
            print("=" * 80)
            print(f"[*] Monitoring time   : {time.time() - self.started:.1f} seconds")
            print(f"[*] Packets observed  : {self.total_packets}")
            print(f"[*] ML predictions    : {self.predictions}")
            print(f"[*] Alerts            : {self.alerts}")
            print(f"[*] Prediction errors : {self.errors}")
            print(f"[*] Active flows      : {len(self.flows)}")
            print(f"[*] Database          : {os.path.abspath(DB_FILE)}")
            print("=" * 80)
            self.db.close()


def main():
    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")

    parser = argparse.ArgumentParser(description="Network IDS Lab Monitor")
    parser.add_argument("--migrate", metavar="PKL_PATH",
                         help="One-time import of an existing nids_moodel.pkl into the SQLite database, then exit.")
    args = parser.parse_args()

    if args.migrate:
        migrate_pickle_to_db(args.migrate)
        return

    print("\n[*] Network IDS Lab starting...\n")
    try:
        LabNIDS().run()
    except Exception as e:
        print(f"\n[ERROR] NIDS could not start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
