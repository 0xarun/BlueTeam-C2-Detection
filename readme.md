---

# 🛡️ MITRE-based Detection Lab  

## 📌 Project Description  
This project demonstrates how to build a **complete blue-team detection lab** inspired by real-world SOC operations, centered around detecting malicious behaviors like **Command and Control (C2) beaconing** and network threats.

✅ **Collecting endpoint telemetry** with Sysmon and forwarding via Winlogbeat/Splunk UF.  
✅ **Monitoring network traffic** with Suricata NIDS.  
✅ **Visualizing threats** using Grafana dashboards connected to Elasticsearch.  
✅ **Creating real-time alerts** via ElastAlert for suspicious behaviors.  
✅ **Beaconing C2** Simulating C2 beaconing with PowerShell for testing detections.  

By implementing this detection lab, you can **gain hands-on SOC experience**, understand the security monitoring pipeline, and prepare for security analyst roles.  

---

## 🔧 Tools Used  
| Tool                      | Description |
|--------------------------|------------|
| **Sysmon**               | System Monitor for Windows, providing detailed system activity logging. |
| **Winlogbeat**           | Forwards Windows event logs to Elasticsearch. |
| **Splunk UF**            | Universal Forwarder sending Windows logs to Splunk server. |
| **Elasticsearch**        | Stores and indexes logs forwarded from Winlogbeat. |
| **Grafana**              | Visualization platform for creating dashboards from Elasticsearch data. |
| **Suricata**             | Network Intrusion Detection System (NIDS) for monitoring traffic. |
| **ElastAlert 2**         | Alert generation framework for Elasticsearch with email notifications. |
| **PowerShell Script**    | Custom script to simulate C2 beaconing behavior. |

---

## 🛠️ Installation & Setup  

### VM-1 for Windows Server

**Specifications**

- **RAM:** 4GB+
- **HDD:** 50GB+
- **OS:** Windows Server 2019

### **1️⃣ Install Sysmon**  
Follow these steps to install and configure Sysmon:  

1. **Download Sysmon from Microsoft Sysinternals:**
   ```powershell
   # Download Sysmon and SwiftOnSecurity's config
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
   Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Sysmon"
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
   ```

2. **Install Sysmon with the configuration:**
   ```powershell
   cd C:\Sysmon
   .\sysmon64.exe -accepteula -i sysmonconfig.xml
   ```

3. **Verify installation:**
   ```powershell
   Get-Service sysmon64
   ```

### **2️⃣ Install Splunk Universal Forwarder**  
Follow these steps to install Splunk UF:  

1. **Download Splunk Universal Forwarder:**
   ```powershell
   # Download Splunk UF from Splunk website and save to C:\
   # Navigate to downloaded MSI file location
   # Install Splunk UF
   ```
2. **Configure Splunk UF for Sysmon:**
   ```powershell
   # Create inputs.conf file in C:\Program Files\SplunkUniversalForwarder\etc\system\local\
   ```
   **inputs.conf:**
   ```
   [default]
   host = WIN-FR3H8BJTJ78
   
   [WinEventLog://Application]
   disabled = 0
   index = wineventlog
   
   [WinEventLog://System]
   disabled = 0
   index = wineventlog
   
   [WinEventLog://Security]
   disabled = 0
   index = wineventlog
   
   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   disabled = 0
   index = sysmon
   renderXml = true
   ```

4. **Restart Splunk UF service:**
   ```powershell
   Restart-Service "SplunkForwarder"
   ```

### **3️⃣ Install Winlogbeat**  
Follow these steps to install and configure Winlogbeat:  

1. **Download Winlogbeat:**
   ```powershell
   # Download latest Winlogbeat from Elastic website
   Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.10.4-windows-x86_64.zip" -OutFile "winlogbeat.zip"
   Expand-Archive -Path "winlogbeat.zip" -DestinationPath "C:\Program Files\Winlogbeat"
   ```

2. **Configure Winlogbeat:**
   ```powershell
   cd "C:\Program Files\Winlogbeat"
   # Edit winlogbeat.yml file
   ```
   
   **Content for winlogbeat.yml:**
   ```yaml
   winlogbeat.event_logs:
     - name: Microsoft-Windows-Sysmon/Operational
     - name: Security
     - name: System
     - name: Application

   output.elasticsearch:
     hosts: ["http://<KALI_IP>:9200"]
   ```

3. **Install and start Winlogbeat service:**
   ```powershell
   .\install-service-winlogbeat.ps1
   Start-Service winlogbeat
   ```

### VM-2 for Kali Linux (SIEM + NIDS Server)

**Specifications**

- **RAM:** 4GB+
- **HDD:** 0GB+
- **OS:** Kali Linux

### **4️⃣ Install Splunk Server**  
Run the following commands to install **Splunk Enterprise** on Kali:  

```bash
# Download Splunk Enterprise
wget -O splunk-8.2.9-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/8.2.9/linux/splunk-8.2.9-linux-2.6-amd64.deb"

# Install Splunk
sudo dpkg -i splunk-8.2.9-linux-2.6-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme

# Configure receiving on port 9997
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:changeme

# Create sysmon and suricata indexes
sudo /opt/splunk/bin/splunk add index sysmon -auth admin:changeme
sudo /opt/splunk/bin/splunk add index suricata -auth admin:changeme
```

Access Splunk Web UI at http://localhost:8000

![Splunk](images/placeholder-splunk-dashboard.png)

### **5️⃣ Install Elasticsearch**  
Follow these steps to install Elasticsearch:  

```bash
# Install Java requirements
sudo apt update && sudo apt install -y default-jre

# Install Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update && sudo apt install elasticsearch -y

# Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

**Update elasticsearch.yml configuration:**
```yaml
network.host: 0.0.0.0
http.port: 9200

xpack.security.enabled: false 
xpack.security.transport.ssl.enabled: false
```

```bash
# Start Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

Verify with: `curl http://localhost:9200`

![Elasticsearch](images/elasticsearch-running.png)

### **6️⃣ Install Grafana**  
Follow these steps to install Grafana:  

```bash
# Add Grafana APT repository
sudo apt-get install -y apt-transport-https software-properties-common
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list

# Install Grafana
sudo apt update && sudo apt install grafana -y

# Start Grafana
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
```

Access Grafana at http://localhost:3000 with default credentials admin/admin

![Grafana](images/grafana-dashboard.png)

### **7️⃣ Install Suricata**  
Install and configure Suricata NIDS:  

```bash
# Install Suricata
sudo apt update && sudo apt install suricata -y

# Edit configuration
sudo nano /etc/suricata/suricata.yaml
```

**Update suricata.yaml for your network interface:**
```yaml
# Find and edit your network interface name
af-packet:
  - interface: eth0  # Change to your interface name
```

```bash
# Update Suricata rules
sudo suricata-update

# Configure outputs for Elasticsearch and Splunk
sudo nano /etc/suricata/suricata.yaml
```

**Configure Suricata Eve output:**
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
```

```bash
# Start Suricata
sudo systemctl enable suricata
sudo systemctl start suricata
```

### **8️⃣ Setup ElastAlert 2**  
Install and configure ElastAlert for email notifications:  

```bash
# Install Python packages
pip3 install elastalert

# Create ElastAlert Directory
mkdir elastalert
cd elastalert

# Configure ElastAlert
nano config.yaml
```
**Update config.yaml with SMTP and Elasticsearch details:**
```yaml
# Basic configuration
es_host: localhost
es_port: 9200
run_every:
  minutes: 1
buffer_time:
  minutes: 15
writeback_index: elastalert_status

# Email configuration
email_reply_to: youremail@domain.com
email_from: youremail@domain.com
smtp_host: smtp.gmail.com
smtp_port: 587
smtp_auth_file: smtp_auth_file.yaml
```

**Create smtp_auth_file.yaml:**
```yaml
user: "your_email@gmail.com"
password: "your_app_password"
```

**Create a rule file for PowerShell beaconing:**
```bash
mkdir rules
nano rules/powershell_beacon.yaml
```

**powershell_beacon.yaml content:**
```yaml
name: PowerShell Beaconing Detection
type: frequency
index: winlogbeat-*
num_events: 5
timeframe:
  minutes: 1
filter:
- query:
    query_string:
      query: "winlog.event_data.Image.keyword: \"*powershell.exe\" AND winlog.event_id:3"
alert:
- email
email:
- your_email@gmail.com
alert_subject: "PowerShell Potential C2 Beaconing Detected"
alert_text: "Detected 5 or more PowerShell network connections within 1 minute.\n
\nSource Host: {0}\nSource User: {1}\nDestination IPs: {2}"
alert_text_args:
- winlog.computer_name
- winlog.event_data.User
- winlog.event_data.DestinationIp
```

```bash
# Run ElastAlert
elastalert-create-index --config config.yaml
elastalert --verbose --config config.yaml
```

```bash
# Output
INFO:elastalert:Queried rule Detect Frequent PowerShell Network Connections from 2024-05-13 11:12:00 to 2024-05-13 11:14:00: 5 hits
INFO:elastalert:Alert for Detect Frequent PowerShell Network Connections at 2024-05-13 11:14:20
INFO:elastalert:Sent email to ['your_email@gmail.com']
```
---

## 🔄 Workflow - Simulating & Detecting C2 Beaconing  

### **📌 Workflow Overview**  
This workflow demonstrates how to simulate and detect C2 beaconing:  
1️⃣ **Create a PowerShell beaconing script** on the Windows victim machine.  
2️⃣ **Execute the script** to simulate periodic outbound connections.  
3️⃣ **Observe the logs** in Splunk and Elasticsearch.  
4️⃣ **Visualize the beaconing pattern** in Grafana dashboards.  
5️⃣ **Receive alerts** via ElastAlert when beaconing threshold is reached.  

### **📌 PowerShell Beaconing Script**  

🔹 **Create beacon.ps1 on Windows machine**  
```powershell
# beacon.ps1 - Simulate C2 beaconing behavior
while ($true) {
    Invoke-WebRequest -Uri "http://KALI_IP:8080/ping" -UseBasicParsing
    Start-Sleep -Seconds 30
}
```

🔹 **Execute the script in PowerShell**  
```powershell
# Run as Administrator 
Set-ExecutionPolicy Bypass -Process Scope
.\beacon.ps1
```
---

## 🚀 Detection & Visualization  

### **Step 1: Create Grafana Dashboards**  
- Log into Grafana (http://localhost:3000) with admin/admin
- Add Elasticsearch as a data source
- Add elasticsearch URL : localhost:9200
- Add Index: winlogbeat-*
- Done 
- Create a new dashboard with the following panels:

**PowerShell Network Connections Panel:**
```
Query:
  event_code:3 AND process.name:*powershell.exe*
Visualization: Time Series
Metrics: Count
Group by: @timestamp (Auto interval)
```

**Top Destination IPs Panel:**
```
Query:
  event_code:3 AND process.name:*powershell.exe*
Visualization: Table
Group by: destination.ip (Terms)
Metrics: Count
```

**Connection Frequency Heatmap:**
```
Query:
  winlog.event_id:3 AND winlog.event_data.Image:*powershell.exe*
Visualization: Heatmap
Metrics: Count
Group by: @timestamp (1m interval)
```

![Grafana Dashboard](https://github.com/user-attachments/assets/placeholder-grafana-c2-dashboard.png)

### **Step 2: Splunk Searches and Alerts**  
- Log into Splunk (http://localhost:8000)
- Create the following searches:

**PowerShell Network Connections:**
```
index=sysmon EventCode=3 Image="*powershell.exe*"
| stats count by DestinationIp, DestinationPort
| sort -count
```

**Beaconing Detection Search:**
```
index=sysmon EventCode=3 Image="*powershell.exe*"
| bucket span=1m _time
| stats count as connection_count by _time, Computer, User, DestinationIp
| where connection_count >= 3
```

**Create a Splunk Alert:**
1. Save the above search as an alert
2. Set to run every 5 minutes
3. Configure email notifications

![Splunk Dashboard](https://github.com/user-attachments/assets/placeholder-splunk-search.png)

### **Step 3: Suricata Rules for Network Detection**  
Create a custom Suricata rule to detect repetitive connections:

```bash
sudo nano /etc/suricata/rules/local.rules
```

**Add the following rule:**
```
# Detect potential C2 beaconing (multiple connections in short timeframe)
alert tcp any any -> any any (msg:"Potential C2 Beaconing Activity"; flow:established; threshold:type threshold, track by_src, count 5, seconds 60; classtype:trojan-activity; sid:1000001; rev:1;)
```

```bash
# Reload Suricata rules
sudo systemctl reload suricata
```

![Suricata Alerts](https://github.com/user-attachments/assets/placeholder-suricata-c2-alerts.png)

---

## 📊 MITRE ATT&CK Alignment  

This detection lab covers the following MITRE ATT&CK techniques:

| Technique ID | Name | Description |
|-------------|------|-------------|
| **T1071** | Application Layer Protocol | Detecting C2 communications using web protocols |
| **T1095** | Non-Application Layer Protocol | Monitoring for unusual network protocols |
| **T1571** | Non-Standard Port | Identifying communications on uncommon ports |
| **T1573** | Encrypted Channel | Detecting encrypted communications patterns |
| **T1105** | Ingress Tool Transfer | Monitoring for file downloads via PowerShell |
| **T1059.001** | PowerShell | Detecting suspicious PowerShell execution |

---

## 🎯 Future Enhancements  
🔹 Add YARA rules for file-based detection.  
🔹 Integrate MISP for threat intelligence.  
🔹 Implement automated containment via Windows Firewall rules.  
🔹 Add Sigma rules for standardized detection logic.  
🔹 Create a Kibana instance alongside Grafana for additional visualizations.  

---

## 🧠 What I Learned  

From building this detection lab, I gained hands-on experience with:

- Setting up and configuring enterprise-grade monitoring tools
- Understanding the complete security monitoring pipeline
- Writing effective detection rules based on behavior, not just IOCs
- Building meaningful visualizations that highlight suspicious patterns
- Implementing real-time alerting for security events
- Using the MITRE ATT&CK framework to categorize and understand threats

For a SOC Analyst role, this project demonstrates practical skills in:
1. Log collection and management
2. Detection engineering
3. Alert triage and response
4. Visualization and reporting

---

## 📜 Resume Impact  

> "Developed a MITRE-based detection lab to identify PowerShell C2 beaconing using Sysmon, Winlogbeat, Splunk UF, and Suricata. Integrated alerts via ElastAlert2 with email notifications. Built real-time dashboards in Grafana and Splunk to visualize endpoint and network behavior."

---

## 📬 Contact  
👤 **Your Name**  
💻 **GitHub:** [Your GitHub Profile]()  
📧 **LinkedIn:** [Your LinkedIn Profile]()  

---
