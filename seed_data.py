"""
Cyber IT/OT Risk Assessment Engine - Seed Data
Populates the database with realistic IT/OT assets and risk scenarios.
"""
from datetime import datetime, timezone, timedelta
import random

def seed_database(db, Asset, Risk, Vulnerability, Mitigation, AuditLog):
    """Populate database with sample IT/OT assets and risks."""
    if Asset.query.count() > 0:
        return  # Already seeded

    # ── ASSETS ──────────────────────────────────────────────
    assets_data = [
        # IT Assets
        {"name": "DC-CORE-01", "asset_type": "IT", "category": "Server",
         "description": "Primary Domain Controller running Active Directory services",
         "owner": "IT Infrastructure Team", "location": "Data Center A - Rack 12",
         "ip_address": "10.0.1.10", "criticality": "Critical",
         "os_firmware": "Windows Server 2022", "vendor": "Dell PowerEdge"},
        {"name": "FW-PERIMETER-01", "asset_type": "IT", "category": "Network Device",
         "description": "Perimeter firewall protecting DMZ and internal network",
         "owner": "Network Security Team", "location": "Data Center A - Rack 01",
         "ip_address": "10.0.0.1", "criticality": "Critical",
         "os_firmware": "FortiOS 7.4.1", "vendor": "Fortinet FortiGate 600F"},
        {"name": "DB-PROD-01", "asset_type": "IT", "category": "Database Server",
         "description": "Production database server hosting ERP and SCADA historian",
         "owner": "Database Admin Team", "location": "Data Center A - Rack 15",
         "ip_address": "10.0.1.50", "criticality": "Critical",
         "os_firmware": "RHEL 9.2 / Oracle 19c", "vendor": "HPE ProLiant DL380"},
        {"name": "WEB-APP-01", "asset_type": "IT", "category": "Web Server",
         "description": "Customer-facing web application server",
         "owner": "DevOps Team", "location": "Cloud - AWS us-east-1",
         "ip_address": "10.0.2.20", "criticality": "High",
         "os_firmware": "Ubuntu 22.04 / Nginx", "vendor": "AWS EC2"},
        {"name": "MAIL-SVR-01", "asset_type": "IT", "category": "Server",
         "description": "Email gateway and exchange server",
         "owner": "IT Infrastructure Team", "location": "Data Center B - Rack 05",
         "ip_address": "10.0.1.30", "criticality": "High",
         "os_firmware": "Windows Server 2022", "vendor": "Dell PowerEdge"},
        # OT Assets
        {"name": "PLC-MAIN-01", "asset_type": "OT", "category": "PLC",
         "description": "Main programmable logic controller for Assembly Line A",
         "owner": "OT Engineering Team", "location": "Plant Floor - Zone 1",
         "ip_address": "192.168.100.10", "criticality": "Critical",
         "os_firmware": "Siemens SIMATIC S7-1500 FW 3.0", "vendor": "Siemens"},
        {"name": "HMI-CTRL-01", "asset_type": "OT", "category": "HMI",
         "description": "Human-Machine Interface for boiler control system",
         "owner": "OT Engineering Team", "location": "Control Room - Station 3",
         "ip_address": "192.168.100.20", "criticality": "High",
         "os_firmware": "WinCC V18", "vendor": "Siemens"},
        {"name": "SCADA-SVR-01", "asset_type": "OT", "category": "SCADA Server",
         "description": "SCADA server managing water treatment process",
         "owner": "OT Security Team", "location": "Control Room - Server Rack",
         "ip_address": "192.168.100.5", "criticality": "Critical",
         "os_firmware": "Windows 10 LTSC / Ignition 8.1", "vendor": "Inductive Automation"},
        {"name": "RTU-FIELD-03", "asset_type": "OT", "category": "RTU",
         "description": "Remote Terminal Unit at substation for power monitoring",
         "owner": "Field Operations", "location": "Substation Charlie",
         "ip_address": "192.168.200.30", "criticality": "High",
         "os_firmware": "SEL-3530 RTAC FW R148", "vendor": "Schweitzer Engineering"},
        {"name": "SW-OT-CORE", "asset_type": "OT", "category": "Network Device",
         "description": "Industrial Ethernet switch for OT network backbone",
         "owner": "OT Network Team", "location": "Plant Floor - MDF",
         "ip_address": "192.168.100.1", "criticality": "High",
         "os_firmware": "Hirschmann HiOS 9.6", "vendor": "Belden Hirschmann"},
        # IoT Assets
        {"name": "CAM-SEC-LOBBY", "asset_type": "IoT", "category": "IP Camera",
         "description": "Security camera in main lobby with facial recognition",
         "owner": "Physical Security Team", "location": "Main Building - Lobby",
         "ip_address": "10.0.5.100", "criticality": "Medium",
         "os_firmware": "Axis OS 11.8", "vendor": "Axis Communications"},
        {"name": "SENSOR-TEMP-01", "asset_type": "IoT", "category": "Environmental Sensor",
         "description": "Temperature and humidity sensor for server room monitoring",
         "owner": "Facilities Team", "location": "Data Center A",
         "ip_address": "10.0.5.50", "criticality": "Low",
         "os_firmware": "Custom FW 2.1", "vendor": "Sensata Technologies"},
    ]

    assets = []
    for a_data in assets_data:
        asset = Asset(**a_data, status='Active')
        db.session.add(asset)
        assets.append(asset)

    db.session.flush()

    # ── RISKS ───────────────────────────────────────────────
    risks_data = [
        {"title": "Ransomware attack on Domain Controller",
         "description": "Risk of ransomware encrypting AD database and disrupting authentication services across the enterprise.",
         "risk_category": "Cyber Attack", "likelihood": 4, "impact": 5,
         "threat_source": "External Threat Actor / APT Group",
         "affected_cia": "Availability, Integrity", "treatment": "Mitigate",
         "risk_owner": "CISO", "asset_idx": 0},
        {"title": "Firewall rule misconfiguration exposing internal services",
         "description": "Incorrect ACL rules could expose internal services to the internet, allowing unauthorized access.",
         "risk_category": "Configuration Error", "likelihood": 3, "impact": 4,
         "threat_source": "Human Error / Change Management Failure",
         "affected_cia": "Confidentiality, Integrity", "treatment": "Mitigate",
         "risk_owner": "Network Security Lead", "asset_idx": 1},
        {"title": "SQL injection on production database",
         "description": "Unpatched web application could allow SQL injection attacks leading to data exfiltration.",
         "risk_category": "Data Breach", "likelihood": 3, "impact": 5,
         "threat_source": "External Attacker", "affected_cia": "Confidentiality",
         "treatment": "Mitigate", "risk_owner": "DBA Lead", "asset_idx": 2},
        {"title": "Phishing attack via email gateway",
         "description": "Spear-phishing emails bypassing email filters could compromise user credentials.",
         "risk_category": "Cyber Attack", "likelihood": 4, "impact": 3,
         "threat_source": "Social Engineering", "affected_cia": "Confidentiality",
         "treatment": "Mitigate", "risk_owner": "Security Awareness Lead", "asset_idx": 4},
        {"title": "Unauthorized firmware modification on PLC",
         "description": "Attacker or insider modifying PLC ladder logic could cause physical damage to equipment or safety incidents.",
         "risk_category": "Insider Threat", "likelihood": 2, "impact": 5,
         "threat_source": "Insider / Nation-State Actor",
         "affected_cia": "Integrity, Availability", "treatment": "Mitigate",
         "risk_owner": "OT Security Manager", "asset_idx": 5},
        {"title": "HMI default credentials exploitation",
         "description": "HMI systems running with default vendor credentials accessible from IT network.",
         "risk_category": "Configuration Error", "likelihood": 4, "impact": 4,
         "threat_source": "Any Network Actor",
         "affected_cia": "Confidentiality, Integrity, Availability",
         "treatment": "Mitigate", "risk_owner": "OT Engineering Lead", "asset_idx": 6},
        {"title": "SCADA server unpatched OS vulnerability",
         "description": "Windows 10 LTSC on SCADA server missing critical security patches due to OT patching constraints.",
         "risk_category": "Cyber Attack", "likelihood": 3, "impact": 5,
         "threat_source": "Remote Code Execution Exploit",
         "affected_cia": "Availability, Integrity", "treatment": "Mitigate",
         "risk_owner": "OT Security Team", "asset_idx": 7},
        {"title": "Supply chain compromise of RTU firmware",
         "description": "Compromised firmware update from vendor could introduce backdoor into field devices.",
         "risk_category": "Supply Chain", "likelihood": 2, "impact": 5,
         "threat_source": "Supply Chain Attack / APT",
         "affected_cia": "Integrity, Availability", "treatment": "Mitigate",
         "risk_owner": "Procurement & Security", "asset_idx": 8},
        {"title": "OT network lateral movement via compromised switch",
         "description": "Flat OT network with insufficient segmentation allowing lateral movement after initial compromise.",
         "risk_category": "Cyber Attack", "likelihood": 3, "impact": 4,
         "threat_source": "Internal Network Attacker",
         "affected_cia": "Confidentiality, Availability", "treatment": "Mitigate",
         "risk_owner": "OT Network Team", "asset_idx": 9},
        {"title": "IP camera feed interception",
         "description": "Unencrypted RTSP streams could be intercepted for surveillance or privacy violation.",
         "risk_category": "Data Breach", "likelihood": 3, "impact": 2,
         "threat_source": "Internal / External Eavesdropper",
         "affected_cia": "Confidentiality", "treatment": "Accept",
         "risk_owner": "Physical Security Lead", "asset_idx": 10},
        {"title": "Web application DDoS attack",
         "description": "Distributed denial of service targeting customer-facing web application.",
         "risk_category": "Cyber Attack", "likelihood": 4, "impact": 3,
         "threat_source": "Hacktivists / Competitors",
         "affected_cia": "Availability", "treatment": "Mitigate",
         "risk_owner": "DevOps Lead", "asset_idx": 3},
        {"title": "Database backup data exposure",
         "description": "Unencrypted database backups stored on network share accessible to unauthorized personnel.",
         "risk_category": "Data Breach", "likelihood": 3, "impact": 4,
         "threat_source": "Insider / Misconfiguration",
         "affected_cia": "Confidentiality", "treatment": "Mitigate",
         "risk_owner": "DBA Lead", "asset_idx": 2, "status": "In Progress"},
        {"title": "PLC denial of service via Modbus flooding",
         "description": "Attacker sending crafted Modbus packets causing PLC CPU to enter fault mode.",
         "risk_category": "Cyber Attack", "likelihood": 2, "impact": 5,
         "threat_source": "Network-based Attack",
         "affected_cia": "Availability", "treatment": "Mitigate",
         "risk_owner": "OT Security Manager", "asset_idx": 5},
        {"title": "Environmental sensor data manipulation",
         "description": "Tampered sensor readings could mask critical temperature events in data center.",
         "risk_category": "Insider Threat", "likelihood": 2, "impact": 3,
         "threat_source": "Insider", "affected_cia": "Integrity",
         "treatment": "Accept", "risk_owner": "Facilities Manager", "asset_idx": 11},
    ]

    risks = []
    for r_data in risks_data:
        asset_idx = r_data.pop('asset_idx')
        r_status = r_data.pop('status', 'Open')
        risk = Risk(
            title=r_data['title'],
            description=r_data['description'],
            risk_category=r_data['risk_category'],
            likelihood=r_data['likelihood'],
            impact=r_data['impact'],
            threat_source=r_data['threat_source'],
            affected_cia=r_data['affected_cia'],
            treatment=r_data['treatment'],
            risk_owner=r_data['risk_owner'],
            asset_id=assets[asset_idx].id,
            status=r_status,
        )
        risk.calculate_risk()
        db.session.add(risk)
        risks.append(risk)

    db.session.flush()

    # ── VULNERABILITIES ─────────────────────────────────────
    vulns_data = [
        {"cve_id": "CVE-2024-21407", "title": "Windows Hyper-V RCE Vulnerability",
         "severity": "Critical", "cvss_score": 9.8, "asset_idx": 0,
         "remediation": "Apply KB5034768 security update"},
        {"cve_id": "CVE-2024-23113", "title": "FortiOS Format String Vulnerability",
         "severity": "Critical", "cvss_score": 9.8, "asset_idx": 1,
         "remediation": "Upgrade to FortiOS 7.4.3 or later"},
        {"cve_id": "CVE-2023-22518", "title": "Oracle Database Privilege Escalation",
         "severity": "High", "cvss_score": 8.1, "asset_idx": 2,
         "remediation": "Apply Oracle Critical Patch Update"},
        {"cve_id": "CVE-2024-3400", "title": "PAN-OS GlobalProtect Command Injection",
         "severity": "Critical", "cvss_score": 10.0, "asset_idx": 1,
         "remediation": "Apply hotfix or disable GlobalProtect portal"},
        {"cve_id": "CVE-2023-6548", "title": "Siemens SIMATIC S7-1500 DoS via OPC-UA",
         "severity": "High", "cvss_score": 7.5, "asset_idx": 5,
         "remediation": "Update to FW 3.0.3 and restrict OPC-UA access"},
        {"cve_id": "CVE-2024-0012", "title": "WinCC HMI Authentication Bypass",
         "severity": "High", "cvss_score": 8.4, "asset_idx": 6,
         "remediation": "Apply Siemens security advisory SSA-432124"},
        {"cve_id": "CVE-2023-38545", "title": "curl/libcurl SOCKS5 Heap Buffer Overflow",
         "severity": "Critical", "cvss_score": 9.8, "asset_idx": 7,
         "remediation": "Update curl to version 8.4.0 or later"},
    ]

    for v_data in vulns_data:
        asset_idx = v_data.pop('asset_idx')
        vuln = Vulnerability(**v_data, asset_id=assets[asset_idx].id, status='Open')
        db.session.add(vuln)

    # ── MITIGATIONS ─────────────────────────────────────────
    mitigations_data = [
        {"title": "Deploy EDR solution on Domain Controller",
         "action_type": "Technical", "status": "In Progress",
         "priority": "Critical", "assigned_to": "SOC Team",
         "effectiveness": 45, "risk_idx": 0},
        {"title": "Implement firewall change management workflow",
         "action_type": "Administrative", "status": "Completed",
         "priority": "High", "assigned_to": "Network Security Lead",
         "effectiveness": 80, "risk_idx": 1},
        {"title": "Deploy Web Application Firewall (WAF)",
         "action_type": "Technical", "status": "Completed",
         "priority": "Critical", "assigned_to": "DevOps Team",
         "effectiveness": 70, "risk_idx": 2},
        {"title": "Implement network segmentation between IT and OT",
         "action_type": "Technical", "status": "In Progress",
         "priority": "Critical", "assigned_to": "OT Network Team",
         "effectiveness": 30, "risk_idx": 8},
        {"title": "Change all default HMI credentials",
         "action_type": "Administrative", "status": "Planned",
         "priority": "Critical", "assigned_to": "OT Engineering",
         "effectiveness": 0, "risk_idx": 5},
        {"title": "Deploy anti-phishing email filters",
         "action_type": "Technical", "status": "Completed",
         "priority": "High", "assigned_to": "Email Admin",
         "effectiveness": 75, "risk_idx": 3},
        {"title": "Implement Modbus deep packet inspection",
         "action_type": "Technical", "status": "Planned",
         "priority": "High", "assigned_to": "OT Security",
         "effectiveness": 0, "risk_idx": 12},
    ]

    for m_data in mitigations_data:
        risk_idx = m_data.pop('risk_idx')
        mit = Mitigation(**m_data, risk_id=risks[risk_idx].id)
        db.session.add(mit)

    # ── AUDIT LOGS ──────────────────────────────────────────
    log = AuditLog(action='System', entity_type='System', entity_name='Database',
                   details='Database seeded with initial IT/OT asset and risk data',
                   user='System')
    db.session.add(log)

    db.session.commit()
    print("  [OK] Database seeded with sample data")
