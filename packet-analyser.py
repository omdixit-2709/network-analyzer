from scapy.all import *
from datetime import datetime
import logging
import json
from collections import defaultdict
import time
import os
import threading
import colorama
from colorama import Fore, Back, Style
import boto3
import yaml
import requests
from typing import Dict, Any

colorama.init()

class CloudWatchDashboard:
    def __init__(self, cloudwatch_client):
        self.cloudwatch = cloudwatch_client
        self.dashboard_name = 'NetworkAnalyzerDashboard'
        self.namespace = 'NetworkAnalyzer'

    def create_dashboard(self):
        try:
            dashboard_body = {
                "widgets": [
                    # Bandwidth Usage Widget
                    {
                        "type": "metric",
                        "x": 0,
                        "y": 0,
                        "width": 12,
                        "height": 6,
                        "properties": {
                            "metrics": [
                                [self.namespace, "Bandwidth", {"label": "Bandwidth (Mbps)"}]
                            ],
                            "view": "timeSeries",
                            "stacked": False,
                            "region": "us-west-2",
                            "title": "Network Bandwidth Usage",
                            "period": 60,
                            "stat": "Average"
                        }
                    },
                    # Packet Rate Widget
                    {
                        "type": "metric",
                        "x": 0,
                        "y": 6,
                        "width": 12,
                        "height": 6,
                        "properties": {
                            "metrics": [
                                [self.namespace, "PacketRate", {"label": "Packets/Second"}]
                            ],
                            "view": "timeSeries",
                            "stacked": False,
                            "region": "us-west-2",
                            "title": "Packet Rate",
                            "period": 60,
                            "stat": "Average"
                        }
                    },
                    # Protocol Distribution Widget
                    {
                        "type": "metric",
                        "x": 12,
                        "y": 0,
                        "width": 12,
                        "height": 6,
                        "properties": {
                            "metrics": [
                                [self.namespace, "TCPPackets", {"label": "TCP"}],
                                [self.namespace, "UDPPackets", {"label": "UDP"}]
                            ],
                            "view": "pie",
                            "region": "us-west-2",
                            "title": "Protocol Distribution",
                            "period": 300,
                            "stat": "Sum"
                        }
                    }
                ]
            }

            self.cloudwatch.put_dashboard(
                DashboardName=self.dashboard_name,
                DashboardBody=json.dumps(dashboard_body)
            )
            print(f"{Fore.GREEN}CloudWatch Dashboard created successfully!{Fore.RESET}")
            print(f"{Fore.CYAN}Dashboard URL: https://{self.cloudwatch.meta.region_name}.console.aws.amazon.com/cloudwatch/home?region={self.cloudwatch.meta.region_name}#dashboards:name={self.dashboard_name}{Fore.RESET}")

        except Exception as e:
            print(f"{Fore.RED}Error creating dashboard: {e}{Fore.RESET}")

class CloudWatchMetrics:
    def __init__(self):
        try:
            # Load AWS configuration
            with open('config/aws_config.yaml', 'r') as f:
                config = yaml.safe_load(f)
            
            # Initialize CloudWatch client
            self.cloudwatch = boto3.client(
                'cloudwatch',
                region_name=config['aws']['region'],
                aws_access_key_id=config['aws']['credentials']['access_key_id'],
                aws_secret_access_key=config['aws']['credentials']['secret_access_key']
            )
            self.namespace = 'NetworkAnalyzer'
            
            # Create dashboard
            self.dashboard = CloudWatchDashboard(self.cloudwatch)
            self.dashboard.create_dashboard()
            
            print(f"{Fore.GREEN}Successfully connected to AWS CloudWatch{Fore.RESET}")
            
        except Exception as e:
            print(f"{Fore.RED}CloudWatch initialization error: {e}{Fore.RESET}")
            self.cloudwatch = None

    def put_metric(self, metric_name: str, value: float, unit: str = 'Count'):
        if self.cloudwatch:
            try:
                self.cloudwatch.put_metric_data(
                    Namespace=self.namespace,
                    MetricData=[{
                        'MetricName': metric_name,
                        'Value': value,
                        'Unit': unit,
                        'Timestamp': datetime.utcnow()
                    }]
                )
            except Exception as e:
                print(f"{Fore.RED}Error sending metric to CloudWatch: {e}{Fore.RESET}")

class AlertManager:
    def __init__(self):
        self.load_config()
        self.alert_history = []

    def load_config(self):
        try:
            with open('config/alert_config.yaml', 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            print(f"{Fore.RED}Alert config loading error: {e}{Fore.RESET}")
            self.config = {
                'thresholds': {
                    'bandwidth_mbps': 100,
                    'packet_rate': 1000,
                    'error_rate': 0.01
                }
            }

    def check_alerts(self, metrics: Dict[str, float]):
        alerts = []
        
        if metrics.get('bandwidth_mbps', 0) > self.config['thresholds']['bandwidth_mbps']:
            alert_msg = f"High bandwidth usage: {metrics['bandwidth_mbps']:.2f} Mbps"
            alerts.append({
                'level': 'WARNING',
                'message': alert_msg
            })
            print(f"\n{Fore.RED}⚠️ ALERT: {alert_msg}{Fore.RESET}")

        if metrics.get('packet_rate', 0) > self.config['thresholds']['packet_rate']:
            alert_msg = f"High packet rate: {metrics['packet_rate']} packets/sec"
            alerts.append({
                'level': 'WARNING',
                'message': alert_msg
            })
            print(f"\n{Fore.RED}⚠️ ALERT: {alert_msg}{Fore.RESET}")

        self.alert_history.extend(alerts)

class NetworkAnalyzer:
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'tcp_packets': 0,
            'udp_packets': 0,
            'bytes_transferred': 0,
            'start_time': datetime.now(),
            'last_update': time.time(),
            'packet_rates': [],
            'current_bandwidth': 0,
            'security_alerts': []
        }
        
        # Initialize components
        self.cloudwatch = CloudWatchMetrics()
        self.alert_manager = AlertManager()
        
        # Setup logging and directories
        self.setup_logging()
        self.setup_directories()

    def setup_logging(self):
        logging.basicConfig(
            filename='logs/network_analysis.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_directories(self):
        for dir_name in ['logs', 'stats', 'config']:
            os.makedirs(dir_name, exist_ok=True)

    def calculate_metrics(self, packet_size):
        current_time = time.time()
        time_diff = current_time - self.stats['last_update']
        
        if time_diff >= 1.0:
            # Calculate bandwidth
            self.stats['current_bandwidth'] = (self.stats['bytes_transferred'] * 8) / (1024 * 1024)  # Mbps
            
            # Calculate packet rate
            duration = (datetime.now() - self.stats['start_time']).total_seconds()
            packet_rate = self.stats['total_packets'] / duration if duration > 0 else 0
            
            # Send metrics to CloudWatch
            self.cloudwatch.put_metric('Bandwidth', self.stats['current_bandwidth'], 'Megabits/Second')
            self.cloudwatch.put_metric('PacketRate', packet_rate, 'Count/Second')
            self.cloudwatch.put_metric('TCPPackets', self.stats['tcp_packets'], 'Count')
            self.cloudwatch.put_metric('UDPPackets', self.stats['udp_packets'], 'Count')
            
            # Check for alerts
            self.alert_manager.check_alerts({
                'bandwidth_mbps': self.stats['current_bandwidth'],
                'packet_rate': packet_rate
            })
            
            # Reset byte counter
            self.stats['bytes_transferred'] = packet_size
            self.stats['last_update'] = current_time
        else:
            self.stats['bytes_transferred'] += packet_size

    def process_packet(self, packet):
        try:
            self.stats['total_packets'] += 1
            packet_size = len(packet)
            
            # Update metrics
            self.calculate_metrics(packet_size)

            if IP in packet:
                if TCP in packet:
                    self.stats['tcp_packets'] += 1
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    self.stats['protocols']['TCP'] += 1
                elif UDP in packet:
                    self.stats['udp_packets'] += 1
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    self.stats['protocols']['UDP'] += 1
                
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                self.display_packet_info(src_ip, dst_ip, src_port, dst_port, packet_size)
            
            if self.stats['total_packets'] % 10 == 0:
                self.display_stats()

        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def display_packet_info(self, src_ip, dst_ip, src_port, dst_port, size):
        print(f"{Fore.CYAN}Packet #{self.stats['total_packets']}: {Fore.RESET}")
        print(f"  {Fore.GREEN}Source: {Fore.YELLOW}{src_ip}:{src_port}")
        print(f"  {Fore.GREEN}Destination: {Fore.YELLOW}{dst_ip}:{dst_port}")
        print(f"  {Fore.GREEN}Size: {Fore.YELLOW}{size} bytes{Fore.RESET}")
        print("-" * 50)

    def display_stats(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        duration = (datetime.now() - self.stats['start_time']).total_seconds()
        packet_rate = self.stats['total_packets'] / duration if duration > 0 else 0
        
        print(f"\n{Fore.CYAN}=== Network Analysis Statistics ==={Fore.RESET}")
        print(f"\n{Fore.GREEN}Running for: {Fore.YELLOW}{int(duration)} seconds")
        print(f"{Fore.GREEN}Total Packets: {Fore.YELLOW}{self.stats['total_packets']}")
        print(f"{Fore.GREEN}Packet Rate: {Fore.YELLOW}{packet_rate:.2f} packets/sec")
        print(f"{Fore.GREEN}Current Bandwidth: {Fore.YELLOW}{self.stats['current_bandwidth']:.2f} Mbps")
        
        print(f"\n{Fore.CYAN}Protocol Distribution:{Fore.RESET}")
        print(f"{Fore.GREEN}TCP Packets: {Fore.YELLOW}{self.stats['tcp_packets']}")
        print(f"{Fore.GREEN}UDP Packets: {Fore.YELLOW}{self.stats['udp_packets']}")
        
        if self.alert_manager.alert_history:
            print(f"\n{Fore.RED}Recent Alerts:{Fore.RESET}")
            for alert in self.alert_manager.alert_history[-3:]:
                print(f"⚠️  {alert['message']}")
        
        print(f"\n{Fore.CYAN}Metrics being sent to CloudWatch{Fore.RESET}")
        print(f"\n{Fore.CYAN}Press Ctrl+C to stop capturing{Fore.RESET}")

    def start_capture(self, interface: str):
        print(f"{Fore.CYAN}Starting packet capture on interface: {Fore.YELLOW}{interface}{Fore.RESET}")
        print(f"{Fore.GREEN}Capture started at: {Fore.YELLOW}{self.stats['start_time']}{Fore.RESET}")
        print(f"{Fore.CYAN}Press Ctrl+C to stop capturing...{Fore.RESET}\n")
        
        try:
            sniff(iface=interface, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Stopping capture...{Fore.RESET}")
        except Exception as e:
            print(f"\n{Fore.RED}Error during capture: {e}{Fore.RESET}")
        finally:
            self.save_stats()

    def save_stats(self):
        stats_to_save = {k: v for k, v in self.stats.items() if k != 'last_update'}
        stats_to_save['duration'] = str(datetime.now() - self.stats['start_time'])
        stats_to_save['alerts'] = self.alert_manager.alert_history
        
        with open('stats/capture_stats.json', 'w') as f:
            json.dump(stats_to_save, f, indent=4, default=str)
        
        print(f"\n{Fore.GREEN}Statistics saved to: {Fore.YELLOW}stats/capture_stats.json{Fore.RESET}")

def main():
    # Create necessary directories first
    os.makedirs('config', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs('stats', exist_ok=True)

    # Create necessary config files if they don't exist
    if not os.path.exists('config/aws_config.yaml'):
        with open('config/aws_config.yaml', 'w') as f:
            yaml.dump({
                'aws': {
                    'region': 'us-west-2',
                    'credentials': {
                        'access_key_id': 'YOUR_ACCESS_KEY',
                        'secret_access_key': 'YOUR_SECRET_KEY'
                    }
                }
            }, f)
        print(f"{Fore.YELLOW}Created aws_config.yaml - please update with your credentials{Fore.RESET}")

    if not os.path.exists('config/alert_config.yaml'):
        with open('config/alert_config.yaml', 'w') as f:
            yaml.dump({
                'thresholds': {
                    'bandwidth_mbps': 100,
                    'packet_rate': 1000,
                    'error_rate': 0.01
                }
            }, f)
        print(f"{Fore.YELLOW}Created alert_config.yaml - please update thresholds if needed{Fore.RESET}")

    # Check if AWS credentials need to be updated
    with open('config/aws_config.yaml', 'r') as f:
        aws_config = yaml.safe_load(f)
        if (aws_config['aws']['credentials']['access_key_id'] == 'YOUR_ACCESS_KEY' or
            aws_config['aws']['credentials']['secret_access_key'] == 'YOUR_SECRET_KEY'):
            print(f"{Fore.RED}Please update AWS credentials in config/aws_config.yaml{Fore.RESET}")
            print(f"{Fore.YELLOW}Do you want to enter AWS credentials now? (y/n): {Fore.RESET}", end='')
            if input().lower() == 'y':
                aws_config['aws']['credentials']['access_key_id'] = input(f"{Fore.CYAN}Enter AWS Access Key ID: {Fore.RESET}")
                aws_config['aws']['credentials']['secret_access_key'] = input(f"{Fore.CYAN}Enter AWS Secret Access Key: {Fore.RESET}")
                aws_config['aws']['region'] = input(f"{Fore.CYAN}Enter AWS Region (default: us-west-2): {Fore.RESET}") or 'us-west-2'
                
                with open('config/aws_config.yaml', 'w') as f:
                    yaml.dump(aws_config, f)
                print(f"{Fore.GREEN}AWS credentials updated successfully!{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}Continuing without AWS CloudWatch integration...{Fore.RESET}")

    analyzer = NetworkAnalyzer()
    
    interfaces = get_working_ifaces()
    print(f"\n{Fore.CYAN}Available interfaces:{Fore.RESET}")
    for i, iface in enumerate(interfaces):
        print(f"{Fore.GREEN}{i}: {Fore.YELLOW}{iface.name}{Fore.RESET}")
    
    try:
        choice = int(input(f"\n{Fore.CYAN}Enter interface number: {Fore.RESET}"))
        interface = interfaces[choice].name
        analyzer.start_capture(interface)
    except (ValueError, IndexError):
        print(f"{Fore.RED}Invalid interface selection{Fore.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program terminated by user{Fore.RESET}")

if __name__ == "__main__":
    main()