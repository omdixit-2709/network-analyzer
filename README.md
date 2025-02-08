# Network Packet Analyzer with AWS CloudWatch Integration

## Overview
A real-time network packet analyzer that captures and analyzes network traffic while sending metrics to AWS CloudWatch for monitoring and visualization.

## Features
- **Real-time packet capture and analysis**
- **Protocol identification** (TCP/UDP)
- **Bandwidth monitoring**
- **AWS CloudWatch integration**
- **Custom dashboard creation**
- **Alert system for network anomalies**
- **Detailed packet statistics**
- **Colorized console output**

---

## Prerequisites
### System Requirements
- Python 3.8 or higher
- Administrator/root privileges
- Active network interface
- AWS account with appropriate permissions

### Required Python Packages
Install the required dependencies using pip:
```bash
pip install scapy colorama boto3 pyyaml requests
```

### AWS Setup
1. **Create an AWS account** (if you don't have one).
2. **Create an IAM user** with CloudWatch permissions.
3. **Create an IAM policy** with the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "cloudwatch:GetMetricData",
                "cloudwatch:PutDashboard",
                "cloudwatch:GetDashboard",
                "cloudwatch:ListDashboards"
            ],
            "Resource": "*"
        }
    ]
}
```
4. **Attach the policy** to your IAM user.
5. **Generate Access Key ID and Secret Access Key** for programmatic access.

---

## Installation
### Clone the Repository
```bash
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Configuration
The program will automatically create configuration files on the first run. Update them with your AWS credentials when prompted.

#### AWS Configuration
**File:** `config/aws_config.yaml`
```yaml
aws:
  region: us-west-2  # Change to your preferred AWS region
  credentials:
    access_key_id: YOUR_ACCESS_KEY
    secret_access_key: YOUR_SECRET_KEY
```

#### Alert Configuration
**File:** `config/alert_config.yaml`
```yaml
thresholds:
  bandwidth_mbps: 100
  packet_rate: 1000
  error_rate: 0.01
```

---

## Usage
### Run the Packet Analyzer
Run the script with administrator privileges:

#### Windows (Command Prompt as Administrator)
```bash
python packet_analyzer.py
```

#### Linux
```bash
sudo python3 packet_analyzer.py
```

When prompted, select your network interface.

### What Happens When You Run the Program?
- Creates necessary directories
- Initializes AWS CloudWatch connection
- Creates a CloudWatch dashboard
- Starts capturing packets
- Displays real-time statistics
- Sends metrics to AWS CloudWatch

### Viewing Metrics in AWS CloudWatch
1. Open **AWS Console**
2. Navigate to **CloudWatch**
3. Select **"Dashboards"** from the left sidebar
4. Click on **"NetworkAnalyzerDashboard"**

---

## Output Files
The program generates the following output files:
```
project/
├── logs/
│   └── network_analysis.log    # Detailed logging
├── stats/
│   └── capture_stats.json      # Captured statistics
└── config/
    ├── aws_config.yaml         # AWS configuration
    └── alert_config.yaml       # Alert thresholds
```

---

## Metrics Tracked
- **Bandwidth usage (Mbps)**
- **Packet rate (packets/second)**
- **Protocol distribution (TCP/UDP)**
- **Total packets processed**
- **Bytes transferred**

### CloudWatch Dashboard Includes:
- **Bandwidth usage graph**
- **Packet rate over time**
- **Protocol distribution pie chart**
- **Custom metrics visualization**

---

## Troubleshooting
### "Access Denied" AWS Errors
- Verify AWS credentials
- Check IAM permissions
- Ensure policy is correctly attached

### No Packets Captured
- Run the script as administrator/root
- Check network interface selection
- Ensure there is active network traffic

### CloudWatch Metrics Not Showing
- Check AWS credentials
- Verify AWS region configuration
- Wait a few minutes for metrics to appear

---

## Contributing
1. **Fork** the repository
2. **Create a feature branch** (`git checkout -b feature-name`)
3. **Commit your changes** (`git commit -m "Added new feature"`)
4. **Push to the branch** (`git push origin feature-name`)
5. **Create a Pull Request**

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author
**Om Dixit**  
- GitHub: [@omdixit](https://github.com/omdixit-2709)
- LinkedIn: [Om Dixit](https://www.linkedin.com/in/om-dixit-47b681251/)

---

## Version History
### **1.0.0**
- Initial Release
- Basic packet capture
- AWS CloudWatch integration

---

## Usage Tips
- Ensure all prerequisites are installed
- Properly configure AWS credentials
- Run the script with administrator privileges
- Monitor CloudWatch dashboard for real-time insights

For any issues or questions, please open an issue on the [GitHub repository](https://github.com/omdixit-2709/network-packet-analyzer/issues).

