"""
Cyber IT/OT Risk Assessment Engine - Database Models
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    asset_type = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default='')
    owner = db.Column(db.String(150), default='Unassigned')
    location = db.Column(db.String(200), default='')
    ip_address = db.Column(db.String(45), default='')
    criticality = db.Column(db.String(20), nullable=False, default='Medium')
    status = db.Column(db.String(20), default='Active')
    os_firmware = db.Column(db.String(150), default='')
    vendor = db.Column(db.String(150), default='')
    purchase_date = db.Column(db.Date, nullable=True)
    last_assessed = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    risks = db.relationship('Risk', backref='asset', lazy=True, cascade='all, delete-orphan')
    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy=True, cascade='all, delete-orphan')

    @property
    def criticality_score(self):
        return {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(self.criticality, 2)

    @property
    def risk_count(self):
        return len(self.risks)

    @property
    def open_risk_count(self):
        return len([r for r in self.risks if r.status in ('Open', 'In Progress')])


class Risk(db.Model):
    __tablename__ = 'risks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default='')
    risk_category = db.Column(db.String(100), nullable=False)
    likelihood = db.Column(db.Integer, nullable=False, default=3)
    impact = db.Column(db.Integer, nullable=False, default=3)
    risk_score = db.Column(db.Integer, nullable=False, default=9)
    risk_level = db.Column(db.String(20), default='Medium')
    threat_source = db.Column(db.String(200), default='')
    affected_cia = db.Column(db.String(50), default='')
    status = db.Column(db.String(30), default='Open')
    treatment = db.Column(db.String(30), default='Mitigate')
    risk_owner = db.Column(db.String(150), default='Unassigned')
    due_date = db.Column(db.Date, nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    identified_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_reviewed = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    mitigations = db.relationship('Mitigation', backref='risk', lazy=True, cascade='all, delete-orphan')

    def calculate_risk(self):
        self.risk_score = self.likelihood * self.impact
        if self.risk_score >= 20:
            self.risk_level = 'Critical'
        elif self.risk_score >= 12:
            self.risk_level = 'High'
        elif self.risk_score >= 6:
            self.risk_level = 'Medium'
        else:
            self.risk_level = 'Low'


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), default='')
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default='')
    severity = db.Column(db.String(20), nullable=False, default='Medium')
    cvss_score = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(30), default='Open')
    remediation = db.Column(db.Text, default='')
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    discovered_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    patched_date = db.Column(db.DateTime, nullable=True)


class Mitigation(db.Model):
    __tablename__ = 'mitigations'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default='')
    action_type = db.Column(db.String(50), default='Technical')
    status = db.Column(db.String(30), default='Planned')
    priority = db.Column(db.String(20), default='Medium')
    assigned_to = db.Column(db.String(150), default='Unassigned')
    due_date = db.Column(db.Date, nullable=True)
    completion_date = db.Column(db.Date, nullable=True)
    effectiveness = db.Column(db.Integer, default=0)
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    entity_name = db.Column(db.String(200), default='')
    details = db.Column(db.Text, default='')
    user = db.Column(db.String(150), default='System')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
