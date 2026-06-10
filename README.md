# 🛡️ Cyber IT/OT Risk Assessment Engine

## 📌 Project Overview

The Cyber IT/OT Risk Assessment Engine is a comprehensive web-based platform designed to manage and assess risks across IT, OT (Operational Technology), and IoT assets. Built with Flask, it features a stunning, modern Obsidian dark-themed dashboard that provides real-time visibility into an organization's security posture. 

The application facilitates complete lifecycle management for assets, risks, vulnerabilities, and mitigations, making it an essential tool for Security Operations Centers (SOC), risk managers, and compliance teams.

## ✨ Key Features

### 📊 Interactive Dashboard
- **Real-Time KPIs:** Instantly view total assets, open risks, active vulnerabilities, average risk scores, and mitigation progress.
- **Dynamic Data Visualization:** Powered by Plotly.js, the dashboard includes:
  - Risk Level Distribution (Donut Chart)
  - Asset Type Breakdown (Bar Chart)
  - Risk Categories (Horizontal Bar Chart)
  - 5×5 Risk Heat Map 
- **Activity Feeds:** Monitor top open risks and a live audit trail of recent system activity.

### 🖥️ Asset Management
- Unified registry for IT, OT, Hybrid, and IoT assets.
- Track critical metadata: categorization, ownership, IP addresses, firmware/OS versions, and location.
- Automatic roll-up of risk counts and vulnerabilities per asset.

### ⚠️ Risk Assessment
- Standardized Likelihood (1-5) × Impact (1-5) scoring model.
- Automatic risk tiering: Critical (≥20), High (≥12), Medium (≥6), Low (<6).
- Track threat sources, affected CIA (Confidentiality, Integrity, Availability) triad, and treatment strategies (Mitigate, Accept, Transfer, Avoid).

### 🎯 5×5 Risk Matrix
- Industry-standard heat map plotting likelihood against impact.
- Interactive cells showing the concentration of risks at each severity level.

### 🔓 Vulnerability Tracking
- Track specific CVEs (Common Vulnerabilities and Exposures) linked to assets.
- Monitor CVSS scores, severity levels, and remediation instructions.

### 🔧 Mitigation Planning
- Define and track mitigation actions against specific risks.
- Monitor progress with effectiveness percentage bars.
- Categorize actions by type (Technical, Administrative, Physical, Procedural).

### 📋 Audit Logging
- Immutable audit trail tracking all Create, Read, Update, and Delete (CRUD) operations.
- Ensures accountability and compliance tracking.

## 🛠️ Technology Stack

- **Backend:** Python 3.10+, Flask, SQLAlchemy (SQLite database)
- **Frontend:** HTML5, Jinja2 templating, Custom CSS3 (Obsidian Dark Theme)
- **Data Visualization:** Plotly.js
- **Forms:** Flask-WTF, WTForms

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher installed on your system.

### 1. Clone or Extract the Project
Ensure you are in the project root directory (`e:\project\Cyber\IT_OT_RISK`).

### 2. Create a Virtual Environment
```bash
python -m venv venv_risk
```

### 3. Activate the Virtual Environment
- **Windows:**
  ```bash
  venv_risk\Scripts\activate
  ```
- **Linux/Mac:**
  ```bash
  source venv_risk/bin/activate
  ```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Run the Application
```bash
python app.py
```
Upon the first run, the SQLite database (`risk_assessment.db`) will be automatically created and seeded with realistic sample data (assets, risks, vulnerabilities, mitigations).

### 6. Access the Platform
Open your web browser and navigate to:
**http://127.0.0.1:5000**

## 🎨 UI/UX Design

The application utilizes a custom-built "Obsidian Dark Theme" featuring:
- **Glassmorphism:** Semi-transparent cards with subtle borders and blur effects.
- **Neon Accents:** Cyan and violet gradients and glows to highlight critical information.
- **Animated Backgrounds:** A slow-pulsing radial gradient background adds depth.
- **Responsive Layout:** A fixed sidebar that collapses on smaller screens, ensuring usability across devices.

## 📁 Directory Structure

```text
IT_OT_RISK/
│
├── app.py                 # Main Flask application and route definitions
├── models.py              # SQLAlchemy database models
├── seed_data.py           # Script to populate the DB with initial sample data
├── requirements.txt       # Python dependencies
├── risk_assessment.db     # SQLite database (generated on first run)
│
├── static/
│   └── style.css          # Master stylesheet (Obsidian Dark Theme)
│
└── templates/             # Jinja2 HTML templates
    ├── base.html          # Master layout with sidebar
    ├── dashboard.html     # Main KPI dashboard
    ├── assets.html        # Asset list view
    ├── asset_form.html    # Add/Edit asset form
    ├── asset_detail.html  # Detailed asset view
    ├── risks.html         # Risk list view
    ├── risk_form.html     # Add/Edit risk form
    ├── risk_detail.html   # Detailed risk view
    ├── risk_matrix.html   # 5x5 Heat map view
    ├── vulnerabilities.html# Vulnerability list view
    ├── mitigations.html   # Mitigation list view
    ├── mitigation_form.html# Add/Edit mitigation form
    └── audit_log.html     # System activity log
```

## 🔐 Security Considerations
*Note: This is a demonstration/internal application. If deploying to production, ensure you:*
- Change the Flask `SECRET_KEY` in `app.py`.
- Use a production WSGI server (like Gunicorn or Waitress) instead of the built-in Flask development server.
- Consider migrating the database from SQLite to PostgreSQL or MySQL for concurrent usage.
- Implement robust user authentication and Role-Based Access Control (RBAC).

---
*Built as part of the Cyber Security Suite.*
