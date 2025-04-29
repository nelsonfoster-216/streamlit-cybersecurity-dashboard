import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import time
import random
from scipy import stats
import seaborn as sns
from sklearn.ensemble import IsolationForest
import plotly.graph_objects as go
import plotly.express as px
import pycountry
import folium
from folium import plugins
from streamlit_folium import folium_static
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut

# Set page config for a wider layout
st.set_page_config(layout="wide", page_title="Sentinel | Cyber Resilience SIEM Dashboard")

# Custom CSS to improve the look
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 20px;
    }
    </style>
""", unsafe_allow_html=True)

# Set up dummy data for cybersecurity incidents
np.random.seed(42)
data = pd.DataFrame({
    'Incident_ID': range(1, 101),
    'Risk_Level': np.random.choice(['Low', 'Medium', 'High'], size=100, p=[0.2, 0.5, 0.3]),
    'Attack_Type': np.random.choice(['Phishing', 'Malware', 'DDoS', 'Ransomware'], size=100),
    'Loss_Amount($)': np.random.randint(1000, 50000, size=100),
    'Date': pd.date_range('2024-01-01', periods=100, freq='D')
})

# Convert datetime to string for better compatibility
data['Date'] = data['Date'].dt.strftime('%Y-%m-%d')

# Initialize session state for alerts, network status, data integrity checks, and anomaly detection results
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'network_status' not in st.session_state:
    st.session_state.network_status = "Connected"
if 'last_alert_time' not in st.session_state:
    st.session_state.last_alert_time = datetime.now()
if 'data_quality_alerts' not in st.session_state:
    st.session_state.data_quality_alerts = []
if 'anomaly_detection_results' not in st.session_state:
    st.session_state.anomaly_detection_results = []

# Initialize session state for various metrics
if 'threat_intel' not in st.session_state:
    st.session_state.threat_intel = {
        'malicious_ips': [],
        'threat_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
        'threat_types': {'Malware': 0, 'Phishing': 0, 'DDoS': 0, 'Ransomware': 0}
    }

# Function to generate random alerts
def generate_alert():
    alert_types = [
        "Suspicious Network Activity",
        "Malware Detection",
        "Unauthorized Access Attempt",
        "Data Exfiltration Attempt",
        "Brute Force Attack",
        "Unusual Process Execution",
        "Registry Modification",
        "Suspicious PowerShell Command",
        "Lateral Movement Detected",
        "Command and Control Traffic"
    ]
    
    severity_weights = {
        "Suspicious Network Activity": ['Medium', 'High'],
        "Malware Detection": ['High', 'Critical'],
        "Unauthorized Access Attempt": ['High', 'Critical'],
        "Data Exfiltration Attempt": ['Critical'],
        "Brute Force Attack": ['Medium', 'High'],
        "Unusual Process Execution": ['Medium', 'High'],
        "Registry Modification": ['Medium'],
        "Suspicious PowerShell Command": ['High'],
        "Lateral Movement Detected": ['Critical'],
        "Command and Control Traffic": ['Critical']
    }
    
    alert_type = random.choice(alert_types)
    severity = random.choice(severity_weights[alert_type])
    
    return {
        'timestamp': datetime.now(),
        'type': alert_type,
        'severity': severity,
        'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
        'status': 'Active',
        'details': generate_alert_details(alert_type),
        'recommended_action': generate_recommended_action(alert_type, severity)
    }

def generate_alert_details(alert_type):
    details = {
        "Suspicious Network Activity": "Unusual outbound traffic pattern detected to known malicious IP",
        "Malware Detection": "Signature match for known ransomware variant",
        "Unauthorized Access Attempt": "Multiple failed login attempts from external IP",
        "Data Exfiltration Attempt": "Large data transfer to unknown external endpoint",
        "Brute Force Attack": "Sequential login attempts detected on multiple accounts",
        "Unusual Process Execution": "Suspicious child process spawned from legitimate application",
        "Registry Modification": "Critical system registry keys modified",
        "Suspicious PowerShell Command": "Encoded PowerShell command execution detected",
        "Lateral Movement Detected": "Suspicious network scanning from internal host",
        "Command and Control Traffic": "Communication with known C2 infrastructure detected"
    }
    return details.get(alert_type, "Additional investigation required")

def generate_recommended_action(alert_type, severity):
    if severity == 'Critical':
        return "Immediate isolation and investigation required"
    elif severity == 'High':
        return "Investigate and contain affected systems"
    else:
        return "Monitor and investigate during business hours"

# Function to perform data quality checks
def check_data_quality(df):
    alerts = []
    
    # Check for missing values
    missing_values = df.isnull().sum()
    if missing_values.any():
        alerts.append({
            'timestamp': datetime.now(),
            'check_type': 'Missing Values',
            'affected_columns': missing_values[missing_values > 0].index.tolist(),
            'severity': 'High'
        })
    
    # Check for data type consistency
    type_inconsistencies = df.apply(lambda x: len(x.unique()) == 1)
    if type_inconsistencies.any():
        alerts.append({
            'timestamp': datetime.now(),
            'check_type': 'Data Type Inconsistency',
            'affected_columns': type_inconsistencies[type_inconsistencies].index.tolist(),
            'severity': 'Medium'
        })
    
    # Check for statistical anomalies
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        z_scores = np.abs(stats.zscore(df[col]))
        if (z_scores > 3).any():
            alerts.append({
                'timestamp': datetime.now(),
                'check_type': 'Statistical Anomaly',
                'affected_column': col,
                'severity': 'High'
            })
    
    return alerts

# Function to detect anomalies using statistical methods
def detect_anomalies(df):
    results = []
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    for col in numeric_cols:
        # Calculate IQR
        Q1 = df[col].quantile(0.25)
        Q3 = df[col].quantile(0.75)
        IQR = Q3 - Q1
        
        # Define bounds
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        
        # Find anomalies
        anomalies = df[(df[col] < lower_bound) | (df[col] > upper_bound)]
        
        if not anomalies.empty:
            results.append({
                'column': col,
                'anomaly_count': len(anomalies),
                'lower_bound': lower_bound,
                'upper_bound': upper_bound,
                'anomaly_values': anomalies[col].tolist()
            })
    
    return results

# Function to calculate data quality metrics
def calculate_quality_metrics(df):
    metrics = {}
    
    # Completeness
    metrics['completeness'] = 1 - (df.isnull().sum().sum() / (df.shape[0] * df.shape[1]))
    
    # Uniqueness
    metrics['uniqueness'] = df.nunique().mean() / len(df)
    
    # Consistency
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        metrics['consistency'] = 1 - (df[numeric_cols].apply(lambda x: np.abs(stats.zscore(x)) > 3).sum().sum() / (len(numeric_cols) * len(df)))
    else:
        metrics['consistency'] = 1.0
    
    # Overall quality score
    metrics['quality_score'] = np.mean(list(metrics.values()))
    
    return metrics

# Function to create data quality visualization
def create_quality_visualization(metrics):
    fig = go.Figure()
    
    # Add radar chart
    fig.add_trace(go.Scatterpolar(
        r=[metrics['completeness'], metrics['uniqueness'], metrics['consistency'], metrics['quality_score']],
        theta=['Completeness', 'Uniqueness', 'Consistency', 'Overall Quality'],
        fill='toself',
        name='Quality Metrics'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1]
            )),
        showlegend=True,
        title="Data Quality Metrics Radar Chart"
    )
    
    return fig

# Function to create anomaly detection visualization
def create_anomaly_visualization(df, column):
    # Use Isolation Forest for anomaly detection
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    anomalies = iso_forest.fit_predict(df[[column]].values)
    
    # Create scatter plot
    fig = px.scatter(
        df,
        x=df.index,
        y=column,
        color=anomalies,
        color_continuous_scale=['blue', 'red'],
        title=f"Anomaly Detection for {column}"
    )
    
    # Add trend line
    fig.add_trace(go.Scatter(
        x=df.index,
        y=df[column].rolling(window=5).mean(),
        mode='lines',
        name='Trend',
        line=dict(color='green')
    ))
    
    return fig

# Function to get country location
def get_country_location(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        if country:
            geolocator = Nominatim(user_agent="my_agent")
            location = geolocator.geocode(country.name)
            if location:
                return (location.latitude, location.longitude)
    except (GeocoderTimedOut, Exception):
        pass
    return None

def create_threat_map(threat_data):
    # Create a base map centered on the world view
    m = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles='CartoDB positron',
        prefer_canvas=True
    )
    
    # Add additional tile layers
    folium.TileLayer('OpenStreetMap').add_to(m)
    folium.TileLayer('CartoDB dark_matter').add_to(m)
    
    # Convert country codes to ISO3 for proper mapping
    def convert_to_iso3(country_code):
        try:
            country = pycountry.countries.get(alpha_2=country_code)
            if country:
                return country.alpha_3
        except:
            return None
    
    # Create a choropleth layer
    country_data = pd.DataFrame(
        threat_data.groupby('source_country').size()
    ).reset_index()
    country_data.columns = ['Country', 'Attacks']
    
    # Convert country codes to ISO3
    country_data['Country'] = country_data['Country'].apply(convert_to_iso3)
    country_data = country_data.dropna()  # Remove any countries that couldn't be converted
    
    # Add the choropleth layer
    choropleth = folium.Choropleth(
        geo_data='https://raw.githubusercontent.com/python-visualization/folium/master/examples/data/world-countries.json',
        name='Threat Distribution',
        data=country_data,
        columns=['Country', 'Attacks'],
        key_on='feature.id',
        fill_color='YlOrRd',
        fill_opacity=0.7,
        line_opacity=0.2,
        legend_name='Number of Attacks',
        highlight=True,
        smooth_factor=0.5
    ).add_to(m)
    
    # Add tooltips to the choropleth layer
    choropleth.geojson.add_child(
        folium.features.GeoJsonTooltip(['name'], labels=False)
    )
    
    # Add markers for each country with attack information
    for idx, row in country_data.iterrows():
        try:
            country = pycountry.countries.get(alpha_3=row['Country'])
            if country:
                location = get_country_location(country.alpha_2)
                if location:
                    folium.CircleMarker(
                        location=location,
                        radius=int(np.log2(row['Attacks'] + 1) * 3),
                        popup=f"{country.name}: {row['Attacks']} attacks",
                        color='red',
                        fill=True,
                        fill_color='red'
                    ).add_to(m)
        except Exception:
            continue
    
    # Add a fullscreen button
    folium.plugins.Fullscreen().add_to(m)
    
    # Add a layer control
    folium.LayerControl().add_to(m)
    
    # Convert to Streamlit with specific dimensions
    return folium_static(m, width=1000, height=500)

# Generate mock threat data
def generate_threat_data():
    # Use proper ISO 2-letter country codes with realistic attack origins
    countries = ['US', 'CN', 'RU', 'GB', 'DE', 'FR', 'JP', 'IN', 'BR', 'KR', 'CA', 'AU', 'IT', 'ES']
    threat_types = [
        'Zero-day Exploit', 'Malware', 'DDoS', 'Phishing', 'Ransomware', 'SQL Injection',
        'Cross-site Scripting', 'Credential Stuffing', 'Man-in-the-Middle', 'Brute Force'
    ]
    severities = ['Critical', 'High', 'Medium', 'Low']
    
    # Generate weighted random choices for countries (some countries might have more attacks)
    country_weights = [0.2, 0.15, 0.15, 0.1, 0.1, 0.05, 0.05, 0.05, 0.05, 0.02, 0.02, 0.02, 0.02, 0.02]
    
    # Generate more varied timestamps with clusters to simulate attack patterns
    base_timestamps = pd.date_range(start='2024-01-01', periods=100, freq='h')
    clustered_timestamps = []
    for ts in base_timestamps:
        # Add cluster of attacks around certain timestamps
        if np.random.random() < 0.3:  # 30% chance of attack cluster
            cluster_size = np.random.randint(1, 5)
            for _ in range(cluster_size):
                offset = timedelta(minutes=np.random.randint(1, 59))
                clustered_timestamps.append(ts + offset)
        else:
            clustered_timestamps.append(ts)
    
    # Generate more realistic attack patterns
    threat_data = {
        'threat_type': [],
        'severity': [],
        'source_country': [],
        'timestamp': sorted(clustered_timestamps),
        'attack_count': [],
        'target_system': [],
        'success_rate': [],
        'data_exfiltration': [],
        'detection_method': []
    }
    
    detection_methods = ['SIEM Alert', 'IDS', 'EDR', 'Firewall Log', 'User Report', 'Threat Intel Feed']
    target_systems = ['Web Server', 'Email Gateway', 'Database', 'Active Directory', 'File Server', 'API Gateway']
    
    for _ in range(len(clustered_timestamps)):
        # Correlate severity with attack type
        attack_type = np.random.choice(threat_types)
        if attack_type in ['Zero-day Exploit', 'Ransomware']:
            severity_weights = [0.4, 0.3, 0.2, 0.1]  # Higher chance of Critical/High
        else:
            severity_weights = [0.2, 0.3, 0.3, 0.2]
        
        threat_data['threat_type'].append(attack_type)
        threat_data['severity'].append(np.random.choice(severities, p=severity_weights))
        threat_data['source_country'].append(np.random.choice(countries, p=country_weights))
        threat_data['attack_count'].append(np.random.randint(5, 50))
        threat_data['target_system'].append(np.random.choice(target_systems))
        threat_data['success_rate'].append(round(np.random.uniform(0, 1), 2))
        threat_data['data_exfiltration'].append(np.random.choice([True, False], p=[0.3, 0.7]))
        threat_data['detection_method'].append(np.random.choice(detection_methods))
    
    return pd.DataFrame(threat_data)

# Generate mock identity data
def generate_identity_data():
    actions = [
        'Login Success', 'Login Failure', 'Password Change', 'Account Locked',
        'Privilege Escalation', 'MFA Challenge', 'Password Reset', 'New Device Login',
        'Unusual Login Time', 'Multiple Login Attempts'
    ]
    locations = ['US', 'UK', 'DE', 'FR', 'JP', 'CN', 'IN', 'BR', 'CA', 'AU']
    departments = ['IT', 'HR', 'Finance', 'Sales', 'Engineering', 'Legal', 'Marketing', 'Operations']
    
    # Generate realistic usernames
    first_letters = ['j', 'k', 'm', 'p', 's', 't']
    last_names = ['smith', 'jones', 'wilson', 'taylor']
    usernames = [
        f"{np.random.choice(first_letters)}{np.random.choice(last_names)}{np.random.randint(1,99)}" 
        for _ in range(50)
    ]
    
    identity_data = {
        'username': usernames,
        'action': np.random.choice(actions, size=50, p=[0.4, 0.2, 0.1, 0.05, 0.05, 0.05, 0.05, 0.05, 0.03, 0.02]),
        'source_ip': [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(50)],
        'timestamp': sorted(pd.date_range(start='2024-01-01', periods=50, freq='h')),
        'location': np.random.choice(locations, size=50),
        'department': np.random.choice(departments, size=50),
        'device_type': np.random.choice(['Desktop', 'Laptop', 'Mobile', 'Tablet'], size=50),
        'auth_method': np.random.choice(['Password', 'MFA', 'SSO', 'Biometric'], size=50),
        'session_duration': [np.random.randint(1, 480) if np.random.random() < 0.8 else 0 for _ in range(50)],  # in minutes
        'risk_score': [round(np.random.uniform(0, 100), 1) for _ in range(50)]
    }
    
    return pd.DataFrame(identity_data)

# Initialize session state with enhanced data
if 'threat_data' not in st.session_state:
    st.session_state.threat_data = generate_threat_data()
if 'identity_data' not in st.session_state:
    st.session_state.identity_data = generate_identity_data()

# Main dashboard title
st.title("Sentinel | Cyber Resilience SIEM Dashboard")

# Create tabs
tab1, tab2, tab3 = st.tabs(["🎯 Threat Intelligence", "🛡️ Security Suite", "👤 Identity Management"])

with tab1:
    st.header("Threat Intelligence Analysis")
    
    # Create two columns for the threat severity and type distribution
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat Severity Distribution
        severity_counts = st.session_state.threat_data['severity'].value_counts()
        fig_severity = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title="Threat Severity Distribution",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig_severity.update_layout(
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_severity, use_container_width=True)
    
    with col2:
        # Threat Types Distribution
        threat_counts = st.session_state.threat_data['threat_type'].value_counts()
        fig_threats = px.bar(
            x=threat_counts.index,
            y=threat_counts.values,
            title="Threat Types Distribution",
            labels={'x': 'Threat Type', 'y': 'Count'},
            color_discrete_sequence=[px.colors.qualitative.Set3[i] for i in range(len(threat_counts))]
        )
        st.plotly_chart(fig_threats, use_container_width=True)
    
    # Geographic Distribution
    st.subheader("Geographic Threat Distribution")
    create_threat_map(st.session_state.threat_data)
    
    # Threat Timeline
    st.subheader("Threat Activity Timeline")
    timeline_data = st.session_state.threat_data.groupby(['timestamp', 'severity']).size().unstack(fill_value=0)
    fig_timeline = px.area(
        timeline_data,
        title="Threat Activity Over Time",
        labels={'timestamp': 'Time', 'value': 'Number of Threats', 'severity': 'Severity'},
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

with tab2:
    st.header("Security Suite Overview")
    
    # Security metrics in a row
    metrics_col1, metrics_col2, metrics_col3, metrics_col4 = st.columns(4)
    
    with metrics_col1:
        st.metric("Active Threats", len(st.session_state.threat_data))
    with metrics_col2:
        st.metric("Critical Alerts", len(st.session_state.threat_data[st.session_state.threat_data['severity'] == 'Critical']))
    with metrics_col3:
        st.metric("Attack Types", len(st.session_state.threat_data['threat_type'].unique()))
    with metrics_col4:
        st.metric("Affected Countries", len(st.session_state.threat_data['source_country'].unique()))
    
    # Recent Threats Table
    st.subheader("Recent Threats")
    recent_threats = st.session_state.threat_data.sort_values('timestamp', ascending=False).head(10)
    st.dataframe(
        recent_threats[['timestamp', 'threat_type', 'severity', 'source_country']],
        use_container_width=True
    )

with tab3:
    st.header("Identity Management")
    
    # Identity metrics
    id_col1, id_col2, id_col3 = st.columns(3)
    
    with id_col1:
        login_success = len(st.session_state.identity_data[st.session_state.identity_data['action'] == 'Login Success'])
        login_failure = len(st.session_state.identity_data[st.session_state.identity_data['action'] == 'Login Failure'])
        success_rate = (login_success / (login_success + login_failure)) * 100
        st.metric("Login Success Rate", f"{success_rate:.1f}%")
    
    with id_col2:
        st.metric("Account Lockouts", 
                 len(st.session_state.identity_data[st.session_state.identity_data['action'] == 'Account Locked']))
    
    with id_col3:
        st.metric("Privilege Escalations",
                 len(st.session_state.identity_data[st.session_state.identity_data['action'] == 'Privilege Escalation']))
    
    # Login activity by location
    st.subheader("Login Activity by Location")
    location_counts = st.session_state.identity_data['location'].value_counts()
    fig_locations = px.bar(
        x=location_counts.index,
        y=location_counts.values,
        title="Login Activity by Location",
        labels={'x': 'Location', 'y': 'Number of Activities'},
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    st.plotly_chart(fig_locations, use_container_width=True)
    
    # Recent activity table
    st.subheader("Recent Identity Activities")
    recent_activities = st.session_state.identity_data.sort_values('timestamp', ascending=False).head(10)
    st.dataframe(
        recent_activities[['timestamp', 'username', 'action', 'location', 'department']],
        use_container_width=True
    )
    
    # Incident Trend Over Time
    st.subheader("Incident Trend Over Time")
    
    # Generate simulated incident data over time
    incident_dates = pd.date_range(start='2024-01-01', end='2024-04-08', freq='D')
    incident_counts = []
    
    # Create a realistic pattern with some variation and an occasional spike
    base_pattern = np.sin(np.linspace(0, 4*np.pi, len(incident_dates))) * 10 + 20  # Sine wave pattern
    
    # Add random variation and some spikes
    for i, val in enumerate(base_pattern):
        if np.random.random() < 0.05:  # 5% chance of a spike
            incident_counts.append(val + np.random.randint(15, 30))
        else:
            incident_counts.append(max(0, val + np.random.randint(-5, 10)))
    
    # Create dataframe
    incident_trend_df = pd.DataFrame({
        'Date': incident_dates,
        'Incident_Count': incident_counts
    })
    
    # Plot the incident trend
    fig_incidents = px.line(
        incident_trend_df, 
        x='Date', 
        y='Incident_Count',
        title="Identity-Related Security Incidents Over Time",
        labels={'Date': 'Date', 'Incident_Count': 'Number of Incidents'},
        line_shape='spline',  # Smooth line
        height=400
    )
    
    # Add some style to the plot
    fig_incidents.update_traces(line=dict(color='#FF4B4B', width=3))
    fig_incidents.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(
            showgrid=True,
            gridcolor='rgba(255,255,255,0.1)',
            tickformat='%Y-%m-%d'
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor='rgba(255,255,255,0.1)'
        ),
        margin=dict(l=0, r=0, t=40, b=0)
    )
    
    st.plotly_chart(fig_incidents, use_container_width=True)
    
    # Add additional context about the incidents
    st.markdown("""
    ### Summary of Identity Incidents
    
    The chart above shows patterns of identity-related security incidents including:
    - Failed login attempts exceeding threshold
    - Account lockouts due to multiple authentication failures
    - Unauthorized privilege escalation attempts
    - Suspicious access from new locations
    - Off-hours authentication activities
    
    **Recent Trend Analysis:** There has been a noticeable increase in identity-related incidents 
    during the past month, with several significant spikes that coincide with the release of 
    new phishing campaigns targeting corporate credentials.
    """)

# Data Quality Analysis Section
st.header("📊 Data Quality Analysis")

# Create tabs for different analysis views
tab1, tab2, tab3 = st.tabs(["Quality Metrics", "Anomaly Detection", "Data Integrity"])

with tab1:
    st.subheader("Data Quality Metrics")
    
    # Calculate and display quality metrics
    quality_metrics = calculate_quality_metrics(data)
    
    # Create columns for metrics display
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Completeness", f"{quality_metrics['completeness']:.2%}")
    with col2:
        st.metric("Uniqueness", f"{quality_metrics['uniqueness']:.2%}")
    with col3:
        st.metric("Consistency", f"{quality_metrics['consistency']:.2%}")
    with col4:
        st.metric("Overall Quality", f"{quality_metrics['quality_score']:.2%}")
    
    # Display radar chart
    st.plotly_chart(create_quality_visualization(quality_metrics))

with tab2:
    st.subheader("Advanced Anomaly Detection")
    
    # Select column for anomaly detection
    selected_column = st.selectbox(
        "Select Column for Anomaly Detection",
        options=data.select_dtypes(include=[np.number]).columns
    )
    
    if selected_column:
        # Display anomaly visualization
        st.plotly_chart(create_anomaly_visualization(data, selected_column))
        
        # Display anomaly statistics
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomalies = iso_forest.fit_predict(data[[selected_column]].values)
        anomaly_count = sum(anomalies == -1)
        
        st.metric("Detected Anomalies", anomaly_count)
        
        # Show anomaly details
        if anomaly_count > 0:
            anomaly_data = data[anomalies == -1][[selected_column]]
            st.write("Anomaly Details:")
            st.dataframe(anomaly_data)

with tab3:
    st.subheader("Data Integrity Checks")
    
    # Run integrity checks
    if st.button("Run Integrity Checks"):
        integrity_results = check_data_quality(data)
        
        # Display results in an expandable section
        with st.expander("View Integrity Check Results"):
            if integrity_results:
                for result in integrity_results:
                    st.warning(f"""
                    **Check Type:** {result['check_type']}
                    **Severity:** {result['severity']}
                    **Timestamp:** {result['timestamp']}
                    """)
            else:
                st.success("No integrity issues detected")
    
    # Display data distribution
    st.subheader("Data Distribution Analysis")
    selected_dist_column = st.selectbox(
        "Select Column for Distribution Analysis",
        options=data.columns
    )
    
    if selected_dist_column:
        fig = px.histogram(
            data,
            x=selected_dist_column,
            marginal="box",
            title=f"Distribution of {selected_dist_column}"
        )
        st.plotly_chart(fig)

# Add a separator
st.markdown("---")

# IPS/EDR Monitoring Section
st.header("🔒 IPS/EDR Monitoring & Network Isolation")

# Create two columns for the monitoring section
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Real-time Alerts")
    
    # Generate new alerts every 30 seconds
    if (datetime.now() - st.session_state.last_alert_time).seconds >= 30:
        new_alert = generate_alert()
        st.session_state.alerts.append(new_alert)
        st.session_state.last_alert_time = datetime.now()
    
    # Display alerts in a table
    if st.session_state.alerts:
        alerts_df = pd.DataFrame(st.session_state.alerts)
        alerts_df['timestamp'] = alerts_df['timestamp'].astype(str)  # Convert datetime to string
        st.dataframe(alerts_df)
    else:
        st.info("No active alerts at this time.")

with col2:
    st.subheader("Network Status")
    status_color = "red" if st.session_state.network_status == "Isolated" else "green"
    st.markdown(f"<h3 style='color: {status_color};'>{st.session_state.network_status}</h3>", unsafe_allow_html=True)
    
    # Network isolation controls
    if st.button("Isolate Network"):
        st.session_state.network_status = "Isolated"
        st.warning("Network has been isolated. Only SIEM communication is allowed.")
        st.session_state.alerts.append({
            'timestamp': datetime.now(),
            'type': "Network Isolation Triggered",
            'severity': 'Critical',
            'source_ip': 'SYSTEM',
            'status': 'Active'
        })
    
    if st.button("Restore Network"):
        st.session_state.network_status = "Connected"
        st.success("Network access has been restored.")
        st.session_state.alerts.append({
            'timestamp': datetime.now(),
            'type': "Network Access Restored",
            'severity': 'Info',
            'source_ip': 'SYSTEM',
            'status': 'Resolved'
        })

# Add a separator
st.markdown("---")

# Sidebar filters
st.sidebar.title("Filter Options")
selected_risk = st.sidebar.multiselect('Select Risk Level', options=['Low', 'Medium', 'High'], default=['Low', 'Medium', 'High'])
selected_attack = st.sidebar.multiselect('Select Attack Type', options=['Phishing', 'Malware', 'DDoS', 'Ransomware'], default=['Phishing', 'Malware', 'DDoS', 'Ransomware'])

# Filter data based on selections
filtered_data = data[(data['Risk_Level'].isin(selected_risk)) & (data['Attack_Type'].isin(selected_attack))]

# Display data table
st.subheader("Incident Data")
st.dataframe(filtered_data)

# Risk level pie chart
st.subheader("Risk Level Distribution")
risk_count = filtered_data['Risk_Level'].value_counts()
fig, ax = plt.subplots()
ax.pie(risk_count, labels=risk_count.index, autopct='%1.1f%%', startangle=90)
ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
st.pyplot(fig)

# Loss amount by attack type bar chart
st.subheader("Total Loss by Attack Type")
loss_by_attack = filtered_data.groupby('Attack_Type')['Loss_Amount($)'].sum()
st.bar_chart(loss_by_attack)

# Summary statistics
st.subheader("Summary Statistics")
st.write(filtered_data.describe())

# Provide download button for filtered data
st.sidebar.download_button(
    label="Download Filtered Data as CSV",
    data=filtered_data.to_csv(index=False),
    file_name='filtered_cybersecurity_data.csv',
    mime='text/csv',
)

# Add footer with custom styling
st.markdown("""
<style>
.footer {
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: #0e1117;
    color: #808495;
    text-align: center;
    padding: 10px;
    font-size: 14px;
    border-top: 1px solid #1f2937;
}
</style>
<div class="footer">
    Copyright 2025. Made with Streamlit v1.44.1, robots and soul by Nelson Foster and Mario Dukes, Co-Founders of ProKofa Solutions. ProKofa | Thrive Resilient®
</div>
""", unsafe_allow_html=True)
