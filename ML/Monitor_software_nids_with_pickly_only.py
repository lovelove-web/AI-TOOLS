import os, sys, time, math, pickle, warnings
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

INTERFACE = r"\Device\NPF_{19B8D6CC-2212-44B4-B0BB-3090629EB758}"
LAB_IP = "192.168.40.129"
KALI_IP = "192.168.40.130"
LAB_NETWORK = "192.168.40.0/24"
MODEL_FILE = "nids_moodel.pkl"
ALERT_LOG = "real_alerts.log"

FEATURE_NAMES = [
    "avg_ipt", "bytes_in", "bytes_out", "dest_ip", "dest_port",
    "duration", "entropy", "num_pkts_in", "num_pkts_out", "proto",
    "src_ip", "src_port", "time_end", "time_start", "total_entropy"
]

def ip_number(ip):
    try:
        a,b,c,d = map(int, str(ip).split("."))
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
    return float(-sum((c/n) * math.log2(c/n) for c in counts.values()))

def is_attack(pred):
    return str(pred).strip().lower() not in {
        "0", "normal", "benign", "safe", "normal traffic"
    }

class LabNIDS:
    def __init__(self):
        self.flows = {}
        self.total_packets = self.predictions = self.alerts = self.errors = 0
        self.started = time.time()
        self.load_model()

    def load_model(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), MODEL_FILE)
        print("[*] Loading trained model...")
        print(f"[*] Model file: {path}")
        if not os.path.exists(path):
            raise FileNotFoundError(path)

        with open(path, "rb") as f:
            p = pickle.load(f)

        self.model = p["model"]
        self.scaler = p["scaler"]
        self.model_name = p.get("model_name", type(self.model).__name__)
        self.accuracy = p.get("accuracy")
        stored = list(p.get("feature_names", []))

        if stored != FEATURE_NAMES:
            raise ValueError(
                f"Saved model features do not match expected schema.\n"
                f"Stored: {stored}\nExpected: {FEATURE_NAMES}"
            )

        if hasattr(self.scaler, "feature_names_in_"):
            sf = list(self.scaler.feature_names_in_)
            if sf != FEATURE_NAMES:
                raise ValueError(f"Scaler feature order mismatch: {sf}")

        print(f"[+] Model: {self.model_name}")
        if self.accuracy is not None:
            try:
                print(f"[+] Training accuracy: {float(self.accuracy)*100:.2f}%")
            except Exception:
                print(f"[+] Training accuracy: {self.accuracy}")
        print("[+] Model loaded successfully")
        print("[+] Number of model features: 15")
        print("[+] Feature schema: " + ", ".join(FEATURE_NAMES))

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
            src,sp,dst,dp,proto = k
            self.flows[k] = {
                "src_ip":src, "src_port":sp, "dst_ip":dst, "dst_port":dp,
                "proto":proto, "start":ts, "last":ts,
                "bytes_in":0, "bytes_out":0,
                "num_pkts_in":0, "num_pkts_out":0,
                "times":[], "sizes":[]
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
            f["times"][i] - f["times"][i-1]
            for i in range(1, len(f["times"]))
        ]
        avg = sum(intervals)/len(intervals) if intervals else 0.0
        e = entropy(f["sizes"])
        return {
            "avg_ipt": float(avg),
            "bytes_in": float(f["bytes_in"]),
            "bytes_out": float(f["bytes_out"]),
            "dest_ip": ip_number(f["dst_ip"]),
            "dest_port": float(f["dst_port"]),
            "duration": float(max(0, f["last"]-f["start"])),
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

    def log_alert(self, f, pred, prob):
        with open(ALERT_LOG, "a", encoding="utf-8") as log:
            log.write(
                f"{datetime.now().isoformat()} | prediction={pred} | "
                f"confidence={prob if prob is not None else 'N/A'} | "
                f"src={f['src_ip']}:{f['src_port']} | "
                f"dst={f['dst_ip']}:{f['dst_port']} | proto={f['proto']}\n"
            )

    def callback(self, p):
        if IP not in p or (p[IP].src != LAB_IP and p[IP].dst != LAB_IP):
            return

        self.total_packets += 1
        ts = float(getattr(p, "time", time.time()))
        f = self.update_flow(p, ts)
        if f is None:
            return

        count = f["num_pkts_in"] + f["num_pkts_out"]
        if count not in {1,2,3,5,10,20,50} and count % 100 != 0:
            return

        try:
            pred, prob = self.predict(f)
            self.predictions += 1
            attack = is_attack(pred)
            status = "ALERT" if attack else "NORMAL"
            conf = f"{prob*100:.1f}%" if prob is not None else "N/A"

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
                f"proto={f['proto']:<3} | {desc:<42.42} | "
                f"ML={str(pred):<15} | P={conf:>6}"
            )

            if attack:
                self.alerts += 1
                self.log_alert(f, pred, prob)
                print("         [!] ALERT logged")

        except Exception as e:
            self.errors += 1
            print(f"[WARNING] ML prediction error: {e}")

    def run(self):
        print("\n" + "="*80)
        print(" NETWORK INTRUSION DETECTION SYSTEM")
        print(" VMware Isolated Lab Mode")
        print("="*80)
        print(f"[*] Capture interface : {INTERFACE}")
        print(f"[*] Windows lab IP    : {LAB_IP}")
        print(f"[*] Kali lab IP       : {KALI_IP}")
        print(f"[*] Network           : {LAB_NETWORK}")
        print("\n[*] Starting network monitoring...")
        print("[*] Waiting for Kali traffic...")
        print("[*] Press CTRL+C to stop and show the summary.\n")
        print("="*145)

        try:
            sniff(iface=INTERFACE, prn=self.callback, store=False)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
        finally:
            print("\n" + "="*80)
            print(" NIDS LAB SUMMARY")
            print("="*80)
            print(f"[*] Monitoring time   : {time.time()-self.started:.1f} seconds")
            print(f"[*] Packets observed  : {self.total_packets}")
            print(f"[*] ML predictions    : {self.predictions}")
            print(f"[*] Alerts            : {self.alerts}")
            print(f"[*] Prediction errors : {self.errors}")
            print(f"[*] Active flows      : {len(self.flows)}")
            print(f"[*] Alert log         : {os.path.abspath(ALERT_LOG)}")
            print("="*80)

def main():
    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")
    print("\n[*] Network IDS Lab starting...\n")
    try:
        LabNIDS().run()
    except Exception as e:
        print(f"\n[ERROR] NIDS could not start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
