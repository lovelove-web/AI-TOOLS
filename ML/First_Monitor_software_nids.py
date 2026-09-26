#!/usr/bin/env python3
"""
Network IDS Monitor 
"""

import pickle
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import warnings
from collections import defaultdict, Counter
import time
import os
import sys
import ipaddress

warnings.filterwarnings('ignore')

class SmartNetworkIDS:
    def __init__(self, model_path='nids_moodel.pkl'):
        """Initialize smart IDS with whitelisting"""
        print("\n" + "="*70)
        print("Network IDS - Reduced False Positives")
        print("="*70 + "\n")
        
        if not os.path.exists(model_path):
            print(f"ERROR: Model file '{model_path}' not found!")
            sys.exit(1)
        
        print("[*] Loading trained model...")
        with open(model_path, 'rb') as f:
            model_package = pickle.load(f)
        
        self.model = model_package['model']
        self.scaler = model_package['scaler']
        self.label_encoders = model_package['label_encoders']
        self.model_name = model_package['model_name']
        self.accuracy = model_package['accuracy']
        
        print(f"[+] Model: {self.model_name} (Accuracy: {self.accuracy:.2%})")
        print("[*] Loading whitelist rules...\n")
        
        # Known good IP ranges (CIDR notation)
        self.whitelist_networks = [
            # Google
            ipaddress.ip_network('142.250.0.0/15'),  # Google services
            ipaddress.ip_network('216.58.192.0/19'),  # Google/YouTube
            ipaddress.ip_network('172.217.0.0/16'),   # Google Cloud
            ipaddress.ip_network('34.64.0.0/10'),     # Google Cloud Platform
            
            # Microsoft
            ipaddress.ip_network('13.64.0.0/11'),     # Azure
            ipaddress.ip_network('20.0.0.0/8'),       # Microsoft services
            ipaddress.ip_network('52.0.0.0/8'),       # Azure/AWS
            ipaddress.ip_network('40.64.0.0/10'),     # Microsoft
            
            # Cloudflare
            ipaddress.ip_network('104.16.0.0/12'),    # Cloudflare CDN
            ipaddress.ip_network('172.64.0.0/13'),    # Cloudflare
            
            # Common CDNs
            ipaddress.ip_network('151.101.0.0/16'),   # Fastly
            ipaddress.ip_network('199.232.0.0/16'),   # Fastly
            
            # Your local network
            ipaddress.ip_network('10.0.0.0/8'),       # Private network
            ipaddress.ip_network('172.16.0.0/12'),    # Private network
            ipaddress.ip_network('192.168.0.0/16'),   # Private network
        ]
        
        # Known safe protocols or patterns
        self.safe_patterns = {
            'QUIC': {'protocol': 'UDP', 'ports': [443, 80]},
            'HTTPS': {'protocol': 'TCP', 'ports': [443]},
            'HTTP': {'protocol': 'TCP', 'ports': [80, 8080]},
            'DNS': {'protocol': 'UDP', 'ports': [53]},
            'Windows_Update': {'protocol': 'TCP', 'ports': [7680]},
        }
        
        # Tracking
        self.connections = defaultdict(lambda: {
            'packets': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'flags': set(),
            'ports': set(),
            'whitelisted': False
        })
        
        self.total_packets = 0
        self.normal_packets = 0
        self.attack_packets = 0
        self.whitelisted_packets = 0
        self.real_alerts = []
        self.false_positives = []
        
        self.feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
    
    def is_whitelisted(self, ip):
        """Check if IP is in whitelist"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.whitelist_networks:
                if ip_obj in network:
                    return True
        except:
            pass
        return False
    
    def is_safe_pattern(self, packet, protocol_type, port):
        """Check if traffic matches known safe patterns"""
        # QUIC/HTTP3 on port 443
        if protocol_type == 'UDP' and port == 443:
            return True, "QUIC/HTTP3 (Modern Web)"
        
        # HTTPS
        if protocol_type == 'TCP' and port == 443:
            return True, "HTTPS (Secure Web)"
        
        # DNS
        if protocol_type == 'UDP' and port == 53:
            return True, "DNS (Domain Lookup)"
        
        # Windows Update
        if protocol_type == 'TCP' and port == 7680:
            return True, "Windows Update Service"
        
        # High ports (return traffic)
        if port > 49152:
            return True, "Ephemeral Port (Return Traffic)"
        
        return False, None
    
    def get_service_name(self, ip):
        """Identify service by IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check specific ranges
            if ip_obj in ipaddress.ip_network('142.250.0.0/15'):
                return "Google"
            elif ip_obj in ipaddress.ip_network('216.58.0.0/16'):
                return "YouTube/Google"
            elif ip_obj in ipaddress.ip_network('13.0.0.0/8') or ip_obj in ipaddress.ip_network('20.0.0.0/8'):
                return "Microsoft"
            elif ip_obj in ipaddress.ip_network('104.16.0.0/12'):
                return "Cloudflare CDN"
            elif ip_obj in ipaddress.ip_network('10.0.0.0/8'):
                return "Local Network"
        except:
            pass
        
        return "Unknown"
    
    def extract_features(self, packet):
        """Extract features from packet"""
        features = {name: 0 for name in self.feature_names}
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                conn_key = f"{src_ip}-{dst_ip}"
                
                conn = self.connections[conn_key]
                conn['packets'] += 1
                conn['last_seen'] = time.time()
                
                if hasattr(packet[IP], 'len'):
                    features['src_bytes'] = packet[IP].len
                
                features['duration'] = int(time.time() - conn['first_seen'])
                
                if TCP in packet:
                    features['protocol_type'] = 0
                    if hasattr(packet[TCP], 'dport'):
                        dport = packet[TCP].dport
                        conn['ports'].add(dport)
                        
                        if dport in [80, 8080]:
                            features['service'] = 0
                        elif dport == 443:
                            features['service'] = 1
                        elif dport == 22:
                            features['service'] = 2
                        else:
                            features['service'] = 4
                    
                    if hasattr(packet[TCP], 'flags'):
                        flags = str(packet[TCP].flags)
                        conn['flags'].update(flags)
                
                elif UDP in packet:
                    features['protocol_type'] = 1
                    if hasattr(packet[UDP], 'dport'):
                        dport = packet[UDP].dport
                        conn['ports'].add(dport)
                        
                        if dport == 53:
                            features['service'] = 5
                        else:
                            features['service'] = 4
                
                elif ICMP in packet:
                    features['protocol_type'] = 2
                    features['service'] = 6
                
                features['count'] = conn['packets']
                
                if 'S' in conn['flags'] and 'F' not in conn['flags']:
                    features['flag'] = 0
                elif 'R' in conn['flags']:
                    features['flag'] = 1
                else:
                    features['flag'] = 2
                
                if src_ip == dst_ip:
                    features['land'] = 1
                
                if conn['packets'] > 3:
                    features['logged_in'] = 1
                
                features['same_srv_rate'] = 1.0
                features['diff_srv_rate'] = 0.0
                
        except Exception:
            pass
        
        return features
    
    def predict_packet(self, packet):
        """Predict with smart filtering"""
        try:
            features = self.extract_features(packet)
            feature_df = pd.DataFrame([features])
            feature_df = feature_df[self.feature_names]
            features_scaled = self.scaler.transform(feature_df)
            
            prediction = self.model.predict(features_scaled)[0]
            
            confidence = 0.5
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features_scaled)[0]
                confidence = max(proba)
            
            return prediction, confidence, features
            
        except Exception:
            return 0, 0.5, None
    
    def packet_callback(self, packet):
        """Smart packet analysis with whitelisting"""
        try:
            if IP not in packet:
                return
            
            self.total_packets += 1
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Determine protocol and port
            if TCP in packet:
                protocol = "TCP"
                port = packet[TCP].dport if hasattr(packet[TCP], 'dport') else 0
                proto_display = f"TCP:{port}"
            elif UDP in packet:
                protocol = "UDP"
                port = packet[UDP].dport if hasattr(packet[UDP], 'dport') else 0
                proto_display = f"UDP:{port}"
            elif ICMP in packet:
                protocol = "ICMP"
                port = 0
                proto_display = "ICMP"
            else:
                return
            
            # Smart filtering
            src_whitelisted = self.is_whitelisted(src_ip)
            dst_whitelisted = self.is_whitelisted(dst_ip)
            is_safe, safe_reason = self.is_safe_pattern(packet, protocol, port)
            
            # Predict
            prediction, confidence, features = self.predict_packet(packet)
            
            # Check for suspicious patterns even in whitelisted traffic
            conn_key = f"{src_ip}-{dst_ip}"
            ports_accessed = len(self.connections[conn_key]['ports'])
            packet_rate = self.connections[conn_key]['packets'] / max(1, time.time() - self.connections[conn_key]['first_seen'])
            
            # Suspicious: too many ports or too fast
            is_suspicious = ports_accessed > 10 or packet_rate > 20
            
            # Override prediction with smart logic
            original_prediction = prediction
            if (src_whitelisted or dst_whitelisted) and is_safe and not is_suspicious:
                prediction = 0  # Force normal
                self.whitelisted_packets += 1
                status = "SAFE"
                color = "\033[94m"  # Blue
                reason = f"{self.get_service_name(dst_ip if dst_ip != src_ip else src_ip)} - {safe_reason}"
            elif prediction == 0:
                self.normal_packets += 1
                status = "NORMAL"
                color = "\033[92m"  # Green
                reason = "Legitimate traffic"
            else:
                # Check if likely false positive
                if (src_whitelisted or dst_whitelisted) or is_safe:
                    self.false_positives.append({
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': proto_display,
                        'service': self.get_service_name(dst_ip),
                        'reason': safe_reason
                    })
                    status = "FP"  # False Positive
                    color = "\033[93m"  # Yellow
                    reason = f"Likely false positive - {safe_reason or 'Known service'}"
                else:
                    # Potential real threat
                    self.attack_packets += 1
                    self.real_alerts.append({
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': proto_display,
                        'confidence': confidence,
                        'ports_accessed': len(self.connections[f"{src_ip}-{dst_ip}"]['ports'])
                    })
                    status = "ALERT"
                    color = "\033[91m"  # Red
                    reason = "SUSPICIOUS - Unknown source/pattern"
                    
                    # Log real alerts
                    with open('real_alerts.log', 'a') as f:
                        f.write(f"{timestamp} | REAL ALERT | {src_ip} -> {dst_ip} | "
                               f"{proto_display} | Confidence: {confidence:.0%}\n")
            
            # Display output
            if status in ["ALERT", "FP"] or self.total_packets % 20 == 0:
                conf_str = f"({confidence:.0%})" if status in ["ALERT", "FP"] else ""
                
                print(f"{color}[{timestamp}] {status:6} {conf_str:5}{'\033[0m'} | "
                      f"{src_ip:15} -> {dst_ip:15} | {proto_display:12} | "
                      f"{reason[:40]:40} | Total: {self.total_packets:4}")
            
        except KeyboardInterrupt:
            raise
        except Exception:
            pass
    
    def start_monitoring(self):
        """Start smart monitoring"""
        print("[*] Starting smart traffic monitoring...")
        print("[*] Whitelisted networks: Google, Microsoft, Cloudflare, Local")
        print("[*] Press Ctrl+C to see summary\n")
        print("="*130)
        print(f"{'Time':^8} | {'Status':^6} | {'Source':^15} -> {'Destination':^15} | "
              f"{'Protocol':^12} | {'Description':^40} | {'Stats':^10}")
        print("="*130)
        
        try:
            try:
                sniff(prn=self.packet_callback, store=False)
            except RuntimeError as e:
                if "layer 2" in str(e).lower() or "winpcap" in str(e).lower():
                    print("\n[!] Switching to Layer 3 mode...\n")
                    sniff(prn=self.packet_callback, store=False, filter="ip")
                else:
                    raise
        except KeyboardInterrupt:
            self.print_summary()
    
    def print_summary(self):
        """Print smart summary"""
        print("\n\n" + "="*70)
        print("SMART IDS ANALYSIS SUMMARY")
        print("="*70)
        
        print(f"\nOverall Statistics:")
        print(f"  Total packets: {self.total_packets}")
        print(f"  Normal: {self.normal_packets} ({self.normal_packets/max(1,self.total_packets)*100:.1f}%)")
        print(f"  Whitelisted (Safe): {self.whitelisted_packets} ({self.whitelisted_packets/max(1,self.total_packets)*100:.1f}%)")
        print(f"  False Positives: {len(self.false_positives)} ({len(self.false_positives)/max(1,self.total_packets)*100:.1f}%)")
        print(f"  Real Alerts: {self.attack_packets} ({self.attack_packets/max(1,self.total_packets)*100:.1f}%)")
        
        if self.real_alerts:
            print(f"\nREAL SECURITY ALERTS ({len(self.real_alerts)} total):")
            for alert in self.real_alerts[-10:]:
                print(f"  [{alert['timestamp']}] {alert['src_ip']:15} -> {alert['dst_ip']:15} | "
                      f"{alert['protocol']:12} | Confidence: {alert['confidence']:.0%} | "
                      f"Ports: {alert['ports_accessed']}")
            print(f"\n Full log: real_alerts.log")
        else:
            print(f"\nNo real threats detected! Your network looks clean.")
        
        if self.false_positives:
            print(f"\n Common False Positives (Top 5):")
            fp_services = Counter([fp['service'] for fp in self.false_positives])
            for service, count in fp_services.most_common(5):
                print(f"  • {service}: {count} packets (normal traffic)")
        
        print(f"\n Recommendation:")
        fp_rate = len(self.false_positives) / max(1, self.total_packets)
        real_rate = self.attack_packets / max(1, self.total_packets)
        
        if real_rate > 0.05:
            print(f"  HIGH ALERT: {real_rate:.1%} suspicious traffic detected!")
            print(f"     → Investigate alerts immediately")
            print(f"     → Consider blocking suspicious IPs")
        elif real_rate > 0.01:
            print(f"   MODERATE: {real_rate:.1%} potentially suspicious traffic")
            print(f"     → Review alerts to confirm threats")
        else:
            print(f"   GOOD: Only {real_rate:.2%} suspicious traffic")
            print(f"     → Network appears secure")
            print(f"     → Most 'attacks' were filtered as false positives")
        
        print("\n" + "="*70)

def main():
    monitor = SmartNetworkIDS()
    monitor.start_monitoring()

if __name__ == "__main__":
    main()