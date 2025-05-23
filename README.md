# Sentinel | Cyber Resilience SIEM Dashboard

A comprehensive Streamlit-based cybersecurity dashboard providing real-time insights into security threats, system performance, and data integrity. This interactive dashboard offers a user-friendly interface for monitoring and analyzing security metrics.

![Dashboard Preview](https://via.placeholder.com/800x450?text=Sentinel+Cyber+Dashboard+Preview)

## Features

### 🎯 Threat Intelligence Analysis
- **Threat Severity Distribution**: Visual breakdown of threats by severity level
- **Threat Types Distribution**: Analysis of different types of attacks
- **Geographic Threat Distribution**: Interactive world map showing attack origins
- **Threat Activity Timeline**: Time-series visualization of threat patterns

### 🛡️ Security Suite Overview
- **Active Threats Metrics**: Real-time summary of active threats
- **Critical Alerts**: Highlighting high-priority security concerns
- **Attack Type Analysis**: Categorization of different attack methodologies
- **Recent Threats Table**: Tabular view of most recent security incidents

### 👤 Identity Management
- **Login Success Rate**: Tracking authentication success metrics
- **Account Lockout Monitoring**: Account access issue tracking
- **Privilege Escalation Tracking**: Monitoring unauthorized permission changes
- **Login Activity by Location**: Geographical analysis of login patterns
- **Identity Activity Timeline**: Historical view of identity-related events

### 📊 Data Quality Analysis
- **Quality Metrics**: Dashboard tracking data completeness, uniqueness, and consistency
- **Anomaly Detection**: Advanced machine learning algorithm to detect outliers
- **Data Integrity Checks**: Validations to ensure data reliability
- **Distribution Analysis**: Statistical analysis of security data patterns

### 🔒 IPS/EDR Monitoring & Network Isolation
- **Real-time Alerts**: Up-to-the-minute security notifications
- **Network Isolation Controls**: Emergency controls to isolate network during breaches
- **System Status Tracking**: Monitoring of protection system status

## Project Structure

```
streamlit-cybersecurity-dashboard/
│
├── cybersecurity_dashboard.py   # Main application file
├── requirements.txt             # Dependencies
└── README.md                    # Documentation
```

### Main Components

#### Utility Functions
- `generate_alert()`: Creates simulated security alerts with varying severity
- `check_data_quality()`: Performs integrity checks on security data
- `detect_anomalies()`: Employs Isolation Forest algorithm for anomaly detection
- `create_threat_map()`: Generates interactive geographical visualization of threats
- `generate_threat_data()`: Creates realistic mock threat data
- `generate_identity_data()`: Simulates identity-related security events

#### Visualization Components
- Pie charts for threat severity distribution
- Bar charts for attack type analysis
- Interactive world map using Folium
- Time-series visualizations for trend analysis
- Radar charts for data quality metrics
- Histograms for statistical distribution analysis

## Technology Stack

- **Frontend Framework**: [Streamlit](https://streamlit.io/)
- **Data Processing**: Python (Pandas, NumPy)
- **Visualization Libraries**:
  - Plotly for interactive charts
  - Matplotlib for static visualizations
  - Folium for geographic mapping
- **Machine Learning**: scikit-learn for anomaly detection
- **Geolocation Services**: GeoPy for coordinate lookup

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersecurity-dashboard.git
   cd streamlit-cybersecurity-dashboard
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   streamlit run cybersecurity_dashboard.py
   ```

5. Open the dashboard:
   - Local URL: http://localhost:8501
   - Network URL will be displayed in terminal

## Dependencies

The application requires the following Python libraries:
- streamlit
- pandas
- numpy
- matplotlib
- scipy
- seaborn
- scikit-learn
- plotly
- pycountry
- folium
- streamlit-folium
- geopy

## Deployment

### Local Deployment with Docker

1. Make sure Docker and Docker Compose are installed on your machine
2. Clone the repository and navigate to the project directory
3. Build and run the Docker container:
   ```bash
   docker-compose up --build
   ```
4. Access the application at http://localhost:8501

### AWS Deployment Options

#### Option 1: Deploy to AWS EC2 (with Docker)

1. Create an EC2 instance (Amazon Linux 2 recommended)
2. Set up security groups to allow inbound traffic on port 80 and 8501
3. Connect to your instance via SSH
4. Install AWS CodeDeploy agent:
   ```bash
   sudo yum update -y
   sudo yum install -y ruby wget
   wget https://aws-codedeploy-us-east-1.s3.amazonaws.com/latest/install
   chmod +x ./install
   sudo ./install auto
   ```
5. Use AWS CodeDeploy to deploy the application from your GitHub repository
6. Access your application via the EC2 instance's public IP address

#### Option 2: Streamlit Cloud (Recommended for Portfolios)

1. Push your code to a GitHub repository
2. Sign up for [Streamlit Cloud](https://streamlit.io/cloud)
3. Deploy your app by connecting to your GitHub repository
4. Embed the provided URL in your portfolio website using an iframe:
   ```html
   <iframe 
     src="https://your-streamlit-app-url.streamlit.app/?embed=true" 
     height="600" 
     width="100%" 
     style="border: none;">
   </iframe>
   ```

#### Option 3: AWS Elastic Beanstalk

1. Install the AWS EB CLI
2. Initialize your project for Elastic Beanstalk:
   ```bash
   eb init -p docker cybersecurity-dashboard
   ```
3. Deploy your application:
   ```bash
   eb create cybersecurity-dashboard-env
   ```
4. Get the URL of your deployed app:
   ```bash
   eb open
   ```

## Use Cases

- **Security Operations Centers (SOC)**: Real-time monitoring of cyber threats
- **IT Security Teams**: Analysis of security incidents and trends
- **Executive Reporting**: High-level security status visualization
- **Data Quality Teams**: Monitoring data integrity of security systems
- **Incident Response**: Quick identification and isolation of security breaches

## Data Sources

The dashboard currently runs on simulated data that mimics real-world cybersecurity incidents. It can be connected to actual data sources like:
- SIEM systems (Splunk, ELK Stack)
- Firewall logs
- IDS/IPS alerts
- User authentication systems
- Threat intelligence feeds

## Future Enhancements

- Integration with real-time security data sources
- Machine learning-based threat prediction
- Automated incident response workflows
- Advanced user behavior analytics
- Custom alerting and notification system

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The Streamlit team for creating an excellent framework for data applications
- The cybersecurity community for insights on effective security monitoring
- Icons and resources from various open-source projects

## Contact

Created by Nelson Foster and Mario Dukes, Co-Founders of ProKofa Solutions.

ProKofa | Thrive Resilient®
