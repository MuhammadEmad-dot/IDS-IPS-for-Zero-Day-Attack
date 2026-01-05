"""
AI-Powered Intrusion Detection & Prevention System for Zero-Day Attacks
Authors: Muhammad Emad Uddin, Muhammad Hassan, Muhammad Haris
"""

import os
import sys
import time
import json
import logging
import warnings
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

import pandas as pd
import numpy as np
from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids_ips_log.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AIIntrusionDetectionSystem:
    """
    AI-Powered IDS/IPS System using One-Class SVM
    """
    
    def __init__(self, model_path: str = 'ids_model.pkl', threshold: float = 0.95):
        """
        Initialize the AI IDS/IPS System
        
        Args:
            model_path: Path to save/load the trained model
            threshold: Anomaly detection threshold (0-1)
        """
        self.model_path = model_path
        self.threshold = threshold
        self.scaler = StandardScaler()
        self.model = None
        self.normal_traffic_stats = None
        self.blocked_ips = set()
        self.threat_log = []
        
        # Load model if exists
        if os.path.exists(model_path):
            self.load_model()
            logger.info(f"Model loaded from {model_path}")
    
    def extract_features_from_pcap(self, pcap_file: str) -> pd.DataFrame:
        """
        Extract features from PCAP file
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Processing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {e}")
            return pd.DataFrame()
        
        features_list = []
        
        # Process packets (limit for performance)
        for i, packet in enumerate(packets[:5000]):
            if i % 1000 == 0:
                logger.info(f"Processed {i} packets...")
            
            # Initialize feature dictionary
            features = {
                'packet_length': len(packet),
                'has_ip': 0,
                'has_tcp': 0,
                'has_udp': 0,
                'has_icmp': 0,
                'src_port': 0,
                'dst_port': 0,
                'ttl': 0,
                'flags': 0,
                'window_size': 0,
                'protocol': 0
            }
            
            # IP layer features
            if IP in packet:
                features['has_ip'] = 1
                features['ttl'] = packet[IP].ttl
                features['protocol'] = packet[IP].proto
                
                # TCP features
                if TCP in packet:
                    features['has_tcp'] = 1
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    features['flags'] = int(packet[TCP].flags)
                    features['window_size'] = packet[TCP].window
                
                # UDP features
                elif UDP in packet:
                    features['has_udp'] = 1
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
                
                # ICMP features
                elif ICMP in packet:
                    features['has_icmp'] = 1
            
            features_list.append(features)
        
        logger.info(f"Extracted {len(features_list)} packets from {pcap_file}")
        return pd.DataFrame(features_list)
    
    def process_dataset_folder(self, dataset_path: str) -> pd.DataFrame:
        """
        Process all PCAP files in the dataset folder
        
        Args:
            dataset_path: Path to dataset folder
        
        Returns:
            Combined DataFrame of all features
        """
        all_features = []
        
        # Walk through all folders and files
        for root, dirs, files in os.walk(dataset_path):
            for file in files:
                # Accept multiple file types
                if any(ext in file.lower() for ext in ['.pcap', '.log', '.cap']):
                    pcap_path = os.path.join(root, file)
                    try:
                        features_df = self.extract_features_from_pcap(pcap_path)
                        
                        if not features_df.empty:
                            all_features.append(features_df)
                            logger.info(f"Added {len(features_df)} samples from {file}")
                    except Exception as e:
                        logger.error(f"Error processing {file}: {e}")
                        continue
        
        if all_features:
            combined_df = pd.concat(all_features, ignore_index=True)
            logger.info(f"Total samples in dataset: {len(combined_df)}")
            return combined_df
        else:
            logger.error("No features extracted from dataset")
            return pd.DataFrame()
    
    def preprocess_features(self, features_df: pd.DataFrame) -> np.ndarray:
        """
        Preprocess features for training
        
        Args:
            features_df: Raw features DataFrame
        
        Returns:
            Preprocessed numpy array
        """
        # Select relevant features
        feature_columns = [
            'packet_length', 'has_ip', 'has_tcp', 'has_udp', 
            'has_icmp', 'src_port', 'dst_port', 'ttl', 
            'flags', 'window_size', 'protocol'
        ]
        
        # Ensure all columns exist
        for col in feature_columns:
            if col not in features_df.columns:
                features_df[col] = 0
        
        X = features_df[feature_columns].values
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled
    
    def train_model(self, dataset_path: str):
        """
        Train the One-Class SVM model on normal traffic
        
        Args:
            dataset_path: Path to normal traffic dataset
        """
        logger.info("Starting model training...")
        
        # Extract features from dataset
        features_df = self.process_dataset_folder(dataset_path)
        
        if features_df.empty:
            logger.error("No features to train on!")
            return
        
        # Preprocess features
        X_train = self.preprocess_features(features_df)
        
        # Create and train One-Class SVM
        self.model = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.1,  # Expected outlier fraction
            verbose=True
        )
        
        logger.info(f"Training on {len(X_train)} samples...")
        self.model.fit(X_train)
        
        # Calculate normal traffic statistics
        train_scores = self.model.score_samples(X_train)
        self.normal_traffic_stats = {
            'mean_score': np.mean(train_scores),
            'std_score': np.std(train_scores),
            'min_score': np.min(train_scores),
            'max_score': np.max(train_scores)
        }
        
        # Save the model
        self.save_model()
        
        logger.info("Model training completed successfully!")
        logger.info(f"Normal traffic stats: {self.normal_traffic_stats}")
    
    def save_model(self):
        """Save the trained model and scaler"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'normal_stats': self.normal_traffic_stats,
            'threshold': self.threshold
        }
        joblib.dump(model_data, self.model_path)
        logger.info(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load the trained model and scaler"""
        model_data = joblib.load(self.model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.normal_traffic_stats = model_data['normal_stats']
        self.threshold = model_data.get('threshold', 0.95)
    
    def extract_live_features(self, packet):
        """
        Extract features from a live packet
        
        Args:
            packet: Scapy packet
        
        Returns:
            (features_dict, src_ip) or (None, None)
        """
        features = {
            'packet_length': len(packet),
            'has_ip': 0,
            'has_tcp': 0,
            'has_udp': 0,
            'has_icmp': 0,
            'src_port': 0,
            'dst_port': 0,
            'ttl': 0,
            'flags': 0,
            'window_size': 0,
            'protocol': 0
        }
        
        # IP layer features
        if IP in packet:
            features['has_ip'] = 1
            features['ttl'] = packet[IP].ttl
            features['protocol'] = packet[IP].proto
            
            # Get source IP for blocking
            src_ip = packet[IP].src
            
            # TCP features
            if TCP in packet:
                features['has_tcp'] = 1
                features['src_port'] = packet[TCP].sport
                features['dst_port'] = packet[TCP].dport
                features['flags'] = int(packet[TCP].flags)
                features['window_size'] = packet[TCP].window
            
            # UDP features
            elif UDP in packet:
                features['has_udp'] = 1
                features['src_port'] = packet[UDP].sport
                features['dst_port'] = packet[UDP].dport
            
            # ICMP features
            elif ICMP in packet:
                features['has_icmp'] = 1
            
            return features, src_ip
        
        return None, None
    
    def calculate_threat_score(self, anomaly_score: float) -> float:
        """
        Calculate threat score (0-100) from anomaly score
        
        Args:
            anomaly_score: Model's anomaly score
        
        Returns:
            Threat score between 0-100
        """
        if self.normal_traffic_stats is None:
            return 0
        
        # Normalize score to 0-100
        min_score = self.normal_traffic_stats['min_score']
        max_score = self.normal_traffic_stats['max_score']
        
        if max_score == min_score:
            return 0
        
        # Lower anomaly score = more anomalous
        threat_score = 100 * (1 - (anomaly_score - min_score) / (max_score - min_score))
        
        return np.clip(threat_score, 0, 100)
    
    def detect_anomaly(self, packet):
        """
        Detect anomaly in a single packet
        
        Args:
            packet: Scapy packet
        
        Returns:
            (anomaly_score, threat_score, src_ip)
        """
        if self.model is None:
            logger.error("Model not loaded!")
            return 0, 0, None
        
        features, src_ip = self.extract_live_features(packet)
        
        if features is None or src_ip is None:
            return 0, 0, None
        
        # Check if IP is already blocked
        if src_ip in self.blocked_ips:
            return 1.0, 100.0, src_ip
        
        # Prepare features for prediction
        feature_columns = [
            'packet_length', 'has_ip', 'has_tcp', 'has_udp', 
            'has_icmp', 'src_port', 'dst_port', 'ttl', 
            'flags', 'window_size', 'protocol'
        ]
        
        # Create feature vector
        feature_vector = np.array([[features[col] for col in feature_columns]])
        
        # Scale features
        try:
            feature_vector_scaled = self.scaler.transform(feature_vector)
        except:
            # If scaler not fitted, return normal score
            return 1.0, 0.0, src_ip
        
        # Get anomaly score
        anomaly_score = self.model.score_samples(feature_vector_scaled)[0]
        
        # Calculate threat score
        threat_score = self.calculate_threat_score(anomaly_score)
        
        return anomaly_score, threat_score, src_ip
    
    def packet_callback(self, packet):
        """
        Callback function for live packet capture
        
        Args:
            packet: Captured packet
        """
        try:
            anomaly_score, threat_score, src_ip = self.detect_anomaly(packet)
            
            if src_ip and threat_score > self.threshold * 100:
                # High threat detected!
                logger.warning(f"🚨 HIGH THREAT DETECTED!")
                logger.warning(f"   Source IP: {src_ip}")
                logger.warning(f"   Threat Score: {threat_score:.2f}/100")
                logger.warning(f"   Anomaly Score: {anomaly_score:.4f}")
                
                # Block the IP
                self.block_ip(src_ip, threat_score)
                
                # Log the incident
                self.log_threat({
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': src_ip,
                    'threat_score': float(threat_score),
                    'anomaly_score': float(anomaly_score),
                    'action_taken': 'BLOCKED',
                    'packet_info': str(packet.summary())
                })
            
            elif threat_score > 70:  # Medium threat
                logger.info(f"⚠️  Suspicious activity: IP={src_ip}, Score={threat_score:.2f}")
                
                self.log_threat({
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': src_ip,
                    'threat_score': float(threat_score),
                    'anomaly_score': float(anomaly_score),
                    'action_taken': 'MONITORING',
                    'packet_info': str(packet.summary())
                })
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def block_ip(self, ip_address: str, threat_score: float):
        """
        Block an IP address
        
        Args:
            ip_address: IP to block
            threat_score: Threat score that triggered blocking
        """
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            
            # Simulate firewall rule update
            logger.info(f"🔒 Blocking IP: {ip_address}")
            logger.info(f"   Adding firewall rule: iptables -A INPUT -s {ip_address} -j DROP")
            
            # In real implementation, you would execute:
            # os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
            
            # Log the blocking action
            blocking_log = {
                'timestamp': datetime.now().isoformat(),
                'blocked_ip': ip_address,
                'threat_score': threat_score,
                'action': 'IP_BLOCKED'
            }
            
            with open('blocked_ips.log', 'a') as f:
                f.write(json.dumps(blocking_log) + '\n')
    
    def log_threat(self, threat_data: Dict):
        """
        Log threat detection
        
        Args:
            threat_data: Dictionary containing threat information
        """
        self.threat_log.append(threat_data)
        
        # Save to log file
        with open('threat_detections.log', 'a') as f:
            f.write(json.dumps(threat_data) + '\n')
    
    def start_live_monitoring(self, interface: str = None, count: int = 0):
        """
        Start live network monitoring
        
        Args:
            interface: Network interface to monitor
            count: Number of packets to capture (0 for infinite)
        """
        logger.info("🚀 Starting AI-Powered IDS/IPS System")
        logger.info(f"   Model: One-Class SVM")
        logger.info(f"   Threshold: {self.threshold*100}%")
        logger.info(f"   Monitoring: {'All interfaces' if interface is None else interface}")
        
        if self.model is None:
            logger.error("❌ Model not trained! Please train or load a model first.")
            return
        
        try:
            # Start packet capture
            sniff(
                prn=self.packet_callback,
                store=0,
                count=count,
                iface=interface,
                filter="ip"  # Only capture IP packets
            )
        except KeyboardInterrupt:
            logger.info("👋 Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
    
    def generate_report(self):
        """Generate security report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_threats_detected': len(self.threat_log),
            'blocked_ips': list(self.blocked_ips),
            'recent_threats': self.threat_log[-10:] if self.threat_log else [],
            'system_status': 'ACTIVE' if self.model else 'INACTIVE'
        }
        
        report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📊 Security report generated: {report_file}")
        return report


def main():
    """Main function to run the IDS/IPS system"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI-Powered IDS/IPS System')
    parser.add_argument('--mode', choices=['train', 'monitor', 'demo'], 
                       default='demo', help='Operation mode')
    parser.add_argument('--dataset', type=str, 
                       default='dataset', help='Path to training dataset')
    parser.add_argument('--interface', type=str, 
                       default=None, help='Network interface to monitor')
    parser.add_argument('--model', type=str, 
                       default='ids_model.pkl', help='Model file path')
    parser.add_argument('--threshold', type=float, 
                       default=0.95, help='Detection threshold (0-1)')
    
    args = parser.parse_args()
    
    # Initialize the system
    ids = AIIntrusionDetectionSystem(
        model_path=args.model,
        threshold=args.threshold
    )
    
    if args.mode == 'train':
        # Train the model
        print("🔧 Training mode selected")
        print(f"   Dataset: {args.dataset}")
        print(f"   Model will be saved to: {args.model}")
        print("\n⚠️  This may take a while depending on dataset size...")
        
        ids.train_model(args.dataset)
        print("✅ Training complete!")
    
    elif args.mode == 'monitor':
        # Start live monitoring
        print("👁️  Starting live monitoring...")
        print("   Press Ctrl+C to stop")
        print("\n" + "="*50)
        
        ids.start_live_monitoring(interface=args.interface)
    
    elif args.mode == 'demo':
        # Run a demonstration
        print("🎬 Running AI-IDS/IPS Demonstration")
        print("="*50)
        
        # Create a demo dataset if none exists
        if not os.path.exists(args.dataset):
            print("Creating demo dataset...")
            os.makedirs('demo_data', exist_ok=True)
            args.dataset = 'demo_data'
        
        # Train or load model
        if not os.path.exists(args.model):
            print("Training demo model...")
            ids.train_model(args.dataset)
        else:
            ids.load_model()
            print("Loaded trained model")
        
        # Simulate some detections
        print("\n🤖 Simulating threat detection...")
        print("-" * 40)
        
        # Simulated threats
        threats = [
            ("192.168.1.100", 1500, 80, "TCP"),
            ("10.0.0.99", 3000, 4444, "TCP"),  # Zero-day attack
            ("172.16.0.77", 50, 31337, "UDP"),  # Zero-day attack
            ("192.168.1.101", 1024, 443, "TCP"),
        ]
        
        for ip, size, port, protocol in threats:
            print(f"\n📡 Analyzing traffic from {ip}")
            print(f"   Packet size: {size}, Port: {port}, Protocol: {protocol}")
            
            # Create a dummy packet for simulation
            from scapy.all import Ether, IP, TCP
            dummy_packet = Ether()/IP(src=ip, dst="192.168.1.1")/TCP(sport=12345, dport=port)
            dummy_packet = dummy_packet.__class__(bytes(dummy_packet))
            
            _, threat_score, _ = ids.detect_anomaly(dummy_packet)
            
            if threat_score > 90:
                print(f"   🚨 ZERO-DAY THREAT DETECTED! Score: {threat_score:.2f}/100")
                print(f"   🛡️  Action: IP {ip} would be BLOCKED")
            elif threat_score > 70:
                print(f"   ⚠️  Suspicious activity: {threat_score:.2f}/100")
            else:
                print(f"   ✅ Normal traffic: {threat_score:.2f}/100")
        
        # Generate report
        print("\n" + "="*50)
        print("📊 Generating Security Report...")
        report = ids.generate_report()
        print(f"   Report saved to: security_report_*.json")
        print(f"   Threats detected: {report['total_threats_detected']}")
        print(f"   System status: {report['system_status']}")
        print("="*50)


if __name__ == "__main__":
    print("="*60)
    print("🤖 AI-Powered Intrusion Detection & Prevention System")
    print("   For Zero-Day Attack Detection")
    print("="*60)
    print()
    
    main()