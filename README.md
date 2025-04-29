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
