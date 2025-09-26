import socket
import struct
import time
import json
import threading
from datetime import datetime
from collections import defaultdict, deque
import matplotlib.pyplot as plt
import numpy as np

class NetworkPacketAnalyzer:
    """
    Network Packet Analyzer for monitoring and analyzing network traffic
    Simulates packet capture and analysis functionality
    """
    
    def __init__(self):
        self.captured_packets = []
        self.traffic_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.anomalies = []
        self.monitoring = False
        self.packet_buffer = deque(maxlen=10000)
        
    def generate_simulated_packet(self, packet_type='normal'):
        """Generate simulated network packets for analysis"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH', 'FTP']
        
        # Simulate different packet types
        if packet_type == 'normal':
            protocol = np.random.choice(protocols, p=[0.4, 0.3, 0.05, 0.1, 0.1, 0.03, 0.02])
            size = np.random.randint(64, 1518)  # Standard Ethernet frame sizes
            src_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            dst_ip = f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.choice([80, 443, 22, 21, 53, 8080, np.random.randint(1024, 65535)])
            
        elif packet_type == 'anomalous':
            # Generate suspicious traffic patterns
            protocol = np.random.choice(['TCP', 'UDP'])
            size = np.random.choice([32, 2000, 9000])  # Unusual sizes
            src_ip = f"192.168.1.{np.random.randint(1, 10)}"  # Limited source range
            dst_ip = f"192.168.1.{np.random.randint(100, 110)}"  # Scan pattern
            src_port = np.random.randint(1, 1024)  # Privileged ports
            dst_port = np.random.randint(1, 1024)
            
        elif packet_type == 'broadcast':
            protocol = 'UDP'
            size = np.random.randint(64, 512)
            src_ip = f"192.168.1.{np.random.randint(1, 255)}"
            dst_ip = "255.255.255.255"  # Broadcast
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.choice([67, 68, 137, 138])  # DHCP, NetBIOS
        
        packet = {
            'timestamp': time.time(),
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': size,
            'flags': self.generate_tcp_flags() if protocol == 'TCP' else None,
            'ttl': np.random.randint(32, 128),
            'packet_type': packet_type
        }
        
        return packet
    
    def generate_tcp_flags(self):
        """Generate TCP flags for realistic packet simulation"""
        flag_combinations = [
            {'SYN': True},  # Connection initiation
            {'SYN': True, 'ACK': True},  # Connection response
            {'ACK': True},  # Data transfer
            {'FIN': True, 'ACK': True},  # Connection termination
            {'RST': True},  # Connection reset
            {'PSH': True, 'ACK': True},  # Push data
        ]
        return np.random.choice(flag_combinations)
    
    def simulate_traffic_capture(self, duration_seconds=30, packets_per_second=100):
        """Simulate network traffic capture"""
        print(f"Starting packet capture simulation for {duration_seconds} seconds...")
        self.monitoring = True
        start_time = time.time()
        packet_id = 0
        
        while self.monitoring and (time.time() - start_time) < duration_seconds:
            # Generate different types of packets
            packet_types = np.random.choice(
                ['normal', 'anomalous', 'broadcast'], 
                p=[0.85, 0.10, 0.05]  # 85% normal, 10% anomalous, 5% broadcast
            )
            
            packet = self.generate_simulated_packet(packet_types)
            packet['id'] = packet_id
            packet_id += 1
            
            # Add to buffers
            self.captured_packets.append(packet)
            self.packet_buffer.append(packet)
            
            # Update statistics
            self.update_traffic_stats(packet)
            
            # Check for anomalies
            self.detect_anomalies(packet)
            
            time.sleep(1.0 / packets_per_second)
        
        self.monitoring = False
        print(f"Capture completed. Total packets captured: {len(self.captured_packets)}")
    
    def update_traffic_stats(self, packet):
        """Update traffic statistics"""
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['total_bytes'] += packet['size']
        self.protocol_stats[packet['protocol']] += 1
        
        # Track bandwidth per second (simplified)
        current_time = int(packet['timestamp'])
        self.traffic_stats[f'bandwidth_{current_time}'] += packet['size']
    
    def detect_anomalies(self, packet):
        """Detect network anomalies and suspicious patterns"""
        current_time = packet['timestamp']
        
        # 1. Port scanning detection (multiple destinations from same source)
        recent_packets = [p for p in self.packet_buffer 
                         if current_time - p['timestamp'] < 10]  # Last 10 seconds
        
        src_ip = packet['src_ip']
        destinations = set(p['dst_ip'] for p in recent_packets if p['src_ip'] == src_ip)
        
        if len(destinations) > 10:  # Scanning more than 10 different IPs
            anomaly = {
                'type': 'port_scan',
                'timestamp': current_time,
                'source_ip': src_ip,
                'target_count': len(destinations),
                'severity': 'high'
            }
            self.anomalies.append(anomaly)
            print(f"ANOMALY DETECTED: Port scan from {src_ip} targeting {len(destinations)} hosts")
        
        # 2. Unusual packet size detection
        if packet['size'] > 8000 or packet['size'] < 40:
            anomaly = {
                'type': 'unusual_size',
                'timestamp': current_time,
                'packet_id': packet['id'],
                'size': packet['size'],
                'severity': 'medium'
            }
            self.anomalies.append(anomaly)
        
        # 3. High frequency from single source (potential DDoS)
        src_packets = [p for p in recent_packets if p['src_ip'] == src_ip]
        if len(src_packets) > 50:  # More than 50 packets in 10 seconds
            anomaly = {
                'type': 'high_frequency',
                'timestamp': current_time,
                'source_ip': src_ip,
                'packet_count': len(src_packets),
                'severity': 'high'
            }
            self.anomalies.append(anomaly)
        
        # 4. Privileged port access attempts
        if packet['dst_port'] < 1024 and packet['protocol'] == 'TCP':
            if packet.get('flags', {}).get('SYN') and not packet.get('flags', {}).get('ACK'):
                anomaly = {
                    'type': 'privileged_port_access',
                    'timestamp': current_time,
                    'source_ip': src_ip,
                    'target_port': packet['dst_port'],
                    'severity': 'medium'
                }
                self.anomalies.append(anomaly)
    
    def analyze_protocol_distribution(self):
        """Analyze protocol distribution in captured traffic"""
        if not self.protocol_stats:
            return {}
        
        total_packets = sum(self.protocol_stats.values())
        distribution = {
            protocol: (count / total_packets) * 100 
            for protocol, count in self.protocol_stats.items()
        }
        
        return distribution
    
    def analyze_bandwidth_utilization(self):
        """Analyze bandwidth utilization over time"""
        if not self.captured_packets:
            return []
        
        # Group packets by second
        time_buckets = defaultdict(int)
        for packet in self.captured_packets:
            bucket = int(packet['timestamp'])
            time_buckets[bucket] += packet['size']
        
        # Convert to timeline
        timeline = []
        if time_buckets:
            start_time = min(time_buckets.keys())
            for bucket in sorted(time_buckets.keys()):
                timeline.append({
                    'time_offset': bucket - start_time,
                    'bytes_per_second': time_buckets[bucket],
                    'mbps': (time_buckets[bucket] * 8) / (1024 * 1024)  # Convert to Mbps
                })
        
        return timeline
    
    def detect_dropped_packets(self, expected_sequence=None):
        """Simulate dropped packet detection"""
        if not expected_sequence:
            # Generate expected sequence based on captured packets
            expected_sequence = list(range(len(self.captured_packets) + 10))
        
        captured_ids = [packet['id'] for packet in self.captured_packets]
        missing_packets = [seq_id for seq_id in expected_sequence if seq_id not in captured_ids]
        
        dropped_count = len(missing_packets)
        drop_rate = (dropped_count / len(expected_sequence)) * 100 if expected_sequence else 0
        
        return {
            'total_expected': len(expected_sequence),
            'total_captured': len(captured_ids),
            'dropped_count': dropped_count,
            'drop_rate_percent': drop_rate,
            'missing_packet_ids': missing_packets[:10]  # Show first 10 missing
        }
    
    def generate_traffic_report(self):
        """Generate comprehensive traffic analysis report"""
        if not self.captured_packets:
            return {'error': 'No packets captured'}
        
        # Basic statistics
        total_packets = len(self.captured_packets)
        total_bytes = sum(p['size'] for p in self.captured_packets)
        duration = max(p['timestamp'] for p in self.captured_packets) - \
                  min(p['timestamp'] for p in self.captured_packets)
        
        # Protocol analysis
        protocol_dist = self.analyze_protocol_distribution()
        
        # Bandwidth analysis
        bandwidth_timeline = self.analyze_bandwidth_utilization()
        avg_bandwidth = np.mean([b['mbps'] for b in bandwidth_timeline]) if bandwidth_timeline else 0
        peak_bandwidth = max([b['mbps'] for b in bandwidth_timeline]) if bandwidth_timeline else 0
        
        # Anomaly summary
        anomaly_summary = defaultdict(int)
        for anomaly in self.anomalies:
            anomaly_summary[anomaly['type']] += 1
        
        # Top talkers (most active IPs)
        ip_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        for packet in self.captured_packets:
            ip_stats[packet['src_ip']]['packets'] += 1
            ip_stats[packet['src_ip']]['bytes'] += packet['size']
        
        top_talkers = sorted(
            ip_stats.items(), 
            key=lambda x: x[1]['packets'], 
            reverse=True
        )[:5]
        
        # Dropped packet analysis
        drop_analysis = self.detect_dropped_packets()
        
        report = {
            'capture_summary': {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'duration_seconds': duration,
                'packets_per_second': total_packets / duration if duration > 0 else 0,
                'average_packet_size': total_bytes / total_packets if total_packets > 0 else 0
            },
            'protocol_distribution': protocol_dist,
            'bandwidth_analysis': {
                'average_mbps': avg_bandwidth,
                'peak_mbps': peak_bandwidth,
                'timeline': bandwidth_timeline
            },
            'anomaly_detection': {
                'total_anomalies': len(self.anomalies),
                'anomaly_types': dict(anomaly_summary),
                'anomaly_details': self.anomalies
            },
            'top_talkers': [
                {'ip': ip, 'packets': stats['packets'], 'bytes': stats['bytes']} 
                for ip, stats in top_talkers
            ],
            'packet_loss_analysis': drop_analysis,
            'timestamp': datetime.now().isoformat()
        }
        
        return report
    
    def plot_traffic_analysis(self):
        """Create visualization plots for traffic analysis"""
        if not self.captured_packets:
            print("No data to plot")
            return
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # 1. Protocol Distribution (Pie Chart)
        protocol_dist = self.analyze_protocol_distribution()
        if protocol_dist:
            protocols = list(protocol_dist.keys())
            percentages = list(protocol_dist.values())
            ax1.pie(percentages, labels=protocols, autopct='%1.1f%%', startangle=90)
            ax1.set_title('Protocol Distribution')
        
        # 2. Bandwidth Over Time
        bandwidth_timeline = self.analyze_bandwidth_utilization()
        if bandwidth_timeline:
            times = [b['time_offset'] for b in bandwidth_timeline]
            mbps_values = [b['mbps'] for b in bandwidth_timeline]
            ax2.plot(times, mbps_values, 'b-', linewidth=2)
            ax2.set_title('Bandwidth Utilization Over Time')
            ax2.set_xlabel('Time (seconds)')
            ax2.set_ylabel('Bandwidth (Mbps)')
            ax2.grid(True, alpha=0.3)
        
        # 3. Packet Size Distribution
        packet_sizes = [p['size'] for p in self.captured_packets]
        ax3.hist(packet_sizes, bins=30, alpha=0.7, color='green', edgecolor='black')
        ax3.set_title('Packet Size Distribution')
        ax3.set_xlabel('Packet Size (bytes)')
        ax3.set_ylabel('Frequency')
        ax3.grid(True, alpha=0.3)
        
        # 4. Anomalies by Type
        if self.anomalies:
            anomaly_types = defaultdict(int)
            for anomaly in self.anomalies:
                anomaly_types[anomaly['type']] += 1
            
            types = list(anomaly_types.keys())
            counts = list(anomaly_types.values())
            ax4.bar(types, counts, color='red', alpha=0.7)
            ax4.set_title('Detected Anomalies by Type')
            ax4.set_xlabel('Anomaly Type')
            ax4.set_ylabel('Count')
            ax4.tick_params(axis='x', rotation=45)
        else:
            ax4.text(0.5, 0.5, 'No Anomalies Detected', 
                    horizontalalignment='center', verticalalignment='center',
                    transform=ax4.transAxes, fontsize=12)
            ax4.set_title('Anomaly Detection')
        
        plt.tight_layout()
        plt.show()
    
    def export_pcap_summary(self, filename='packet_analysis.json'):
        """Export analysis results to JSON file"""
        report = self.generate_traffic_report()
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Analysis report exported to {filename}")
        return filename

def demonstrate_packet_analyzer():
    """Demonstrate packet analyzer functionality"""
    print("=== Network Packet Analyzer Demo ===\n")
    
    # Create analyzer
    analyzer = NetworkPacketAnalyzer()
    
    # Start traffic capture simulation
    print("Starting network traffic capture...")
    
    # Run capture in separate thread
    capture_thread = threading.Thread(
        target=analyzer.simulate_traffic_capture,
        args=(20, 75)  # 20 seconds, 75 packets/second
    )
    capture_thread.start()
    capture_thread.join()
    
    # Generate and display analysis
    print("\n=== ANALYSIS RESULTS ===")
    report = analyzer.generate_traffic_report()
    
    print(f"Total Packets Captured: {report['capture_summary']['total_packets']}")
    print(f"Total Bytes: {report['capture_summary']['total_bytes']:,}")
    print(f"Average Packet Size: {report['capture_summary']['average_packet_size']:.1f} bytes")
    print(f"Packets per Second: {report['capture_summary']['packets_per_second']:.1f}")
    
    print(f"\nProtocol Distribution:")
    for protocol, percentage in report['protocol_distribution'].items():
        print(f"  {protocol}: {percentage:.1f}%")
    
    print(f"\nBandwidth Analysis:")
    print(f"  Average: {report['bandwidth_analysis']['average_mbps']:.3f} Mbps")
    print(f"  Peak: {report['bandwidth_analysis']['peak_mbps']:.3f} Mbps")
    
    print(f"\nAnomalies Detected: {report['anomaly_detection']['total_anomalies']}")
    if report['anomaly_detection']['anomaly_types']:
        for anomaly_type, count in report['anomaly_detection']['anomaly_types'].items():
            print(f"  {anomaly_type}: {count}")
    
    print(f"\nTop 3 Talkers:")
    for i, talker in enumerate(report['top_talkers'][:3], 1):
        print(f"  {i}. {talker['ip']}: {talker['packets']} packets, {talker['bytes']:,} bytes")
    
    print(f"\nPacket Loss Analysis:")
    print(f"  Expected: {report['packet_loss_analysis']['total_expected']}")
    print(f"  Captured: {report['packet_loss_analysis']['total_captured']}")
    print(f"  Drop Rate: {report['packet_loss_analysis']['drop_rate_percent']:.2f}%")
    
    # Create visualizations
    print("\nGenerating traffic analysis plots...")
    analyzer.plot_traffic_analysis()
    
    # Export results
    filename = analyzer.export_pcap_summary()
    print(f"Detailed analysis saved to: {filename}")

if __name__ == "__main__":
    demonstrate_packet_analyzer()