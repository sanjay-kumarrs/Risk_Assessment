"""
╔══════════════════════════════════════════════════════════════════╗
║          Cyber IT/OT Risk Assessment & Asset Management         ║
║                        Flask Application                         ║
╚══════════════════════════════════════════════════════════════════╝
"""
import os
import json
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from models import db, Asset, Risk, Vulnerability, Mitigation, AuditLog
from seed_data import seed_database

# ─── App Config ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-risk-engine-2026'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "risk_assessment.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()
    seed_database(db, Asset, Risk, Vulnerability, Mitigation, AuditLog)


# ─── Helpers ────────────────────────────────────────────────
def log_action(action, entity_type, entity_id=None, entity_name='', details=''):
    """Create an audit log entry."""
    log = AuditLog(action=action, entity_type=entity_type,
                   entity_id=entity_id, entity_name=entity_name,
                   details=details, user='Admin')
    db.session.add(log)
    db.session.commit()


# ═══════════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════════
@app.route('/')
def dashboard():
    """Main dashboard with risk overview."""
    total_assets = Asset.query.count()
    active_assets = Asset.query.filter_by(status='Active').count()
    total_risks = Risk.query.count()
    open_risks = Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).count()
    critical_risks = Risk.query.filter_by(risk_level='Critical').filter(
        Risk.status.in_(['Open', 'In Progress'])).count()
    high_risks = Risk.query.filter_by(risk_level='High').filter(
        Risk.status.in_(['Open', 'In Progress'])).count()
    total_vulns = Vulnerability.query.count()
    open_vulns = Vulnerability.query.filter_by(status='Open').count()

    # Risk distribution
    risk_levels = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for risk in Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).all():
        if risk.risk_level in risk_levels:
            risk_levels[risk.risk_level] += 1

    # Asset type distribution
    asset_types = {}
    for asset in Asset.query.filter_by(status='Active').all():
        asset_types[asset.asset_type] = asset_types.get(asset.asset_type, 0) + 1

    # Risk category distribution
    risk_categories = {}
    for risk in Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).all():
        risk_categories[risk.risk_category] = risk_categories.get(risk.risk_category, 0) + 1

    # Top risks
    top_risks = Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).order_by(
        Risk.risk_score.desc()).limit(5).all()

    # Recent activity
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    # Risk matrix data (5x5)
    risk_matrix = [[0]*5 for _ in range(5)]
    for risk in Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).all():
        li = min(risk.likelihood, 5) - 1
        ii = min(risk.impact, 5) - 1
        risk_matrix[li][ii] += 1

    # Mitigation progress
    total_mitigations = Mitigation.query.count()
    completed_mitigations = Mitigation.query.filter_by(status='Completed').count()
    mitigation_pct = round((completed_mitigations / total_mitigations * 100) if total_mitigations > 0 else 0)

    # Average risk score
    all_open_risks = Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).all()
    avg_risk = round(sum(r.risk_score for r in all_open_risks) / len(all_open_risks), 1) if all_open_risks else 0

    return render_template('dashboard.html',
        total_assets=total_assets, active_assets=active_assets,
        total_risks=total_risks, open_risks=open_risks,
        critical_risks=critical_risks, high_risks=high_risks,
        total_vulns=total_vulns, open_vulns=open_vulns,
        risk_levels=risk_levels, asset_types=asset_types,
        risk_categories=risk_categories, top_risks=top_risks,
        recent_logs=recent_logs, risk_matrix=risk_matrix,
        mitigation_pct=mitigation_pct, avg_risk=avg_risk,
        total_mitigations=total_mitigations,
        completed_mitigations=completed_mitigations)


# ═══════════════════════════════════════════════════════════
#  ASSET MANAGEMENT
# ═══════════════════════════════════════════════════════════
@app.route('/assets')
def assets_list():
    """List all assets with filtering."""
    asset_type = request.args.get('type', '')
    criticality = request.args.get('criticality', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')

    query = Asset.query
    if asset_type:
        query = query.filter_by(asset_type=asset_type)
    if criticality:
        query = query.filter_by(criticality=criticality)
    if status:
        query = query.filter_by(status=status)
    if search:
        query = query.filter(Asset.name.contains(search) | Asset.description.contains(search))

    assets = query.order_by(Asset.created_at.desc()).all()
    return render_template('assets.html', assets=assets,
                           filter_type=asset_type, filter_crit=criticality,
                           filter_status=status, search=search)


@app.route('/assets/add', methods=['GET', 'POST'])
def asset_add():
    """Add a new asset."""
    if request.method == 'POST':
        asset = Asset(
            name=request.form['name'],
            asset_type=request.form['asset_type'],
            category=request.form['category'],
            description=request.form.get('description', ''),
            owner=request.form.get('owner', 'Unassigned'),
            location=request.form.get('location', ''),
            ip_address=request.form.get('ip_address', ''),
            criticality=request.form['criticality'],
            status=request.form.get('status', 'Active'),
            os_firmware=request.form.get('os_firmware', ''),
            vendor=request.form.get('vendor', ''),
        )
        db.session.add(asset)
        db.session.commit()
        log_action('Created', 'Asset', asset.id, asset.name, f'New {asset.asset_type} asset registered')
        flash(f'Asset "{asset.name}" created successfully!', 'success')
        return redirect(url_for('assets_list'))
    return render_template('asset_form.html', asset=None, action='Add')


@app.route('/assets/<int:id>')
def asset_detail(id):
    """View asset details with associated risks and vulnerabilities."""
    asset = Asset.query.get_or_404(id)
    return render_template('asset_detail.html', asset=asset)


@app.route('/assets/<int:id>/edit', methods=['GET', 'POST'])
def asset_edit(id):
    """Edit an existing asset."""
    asset = Asset.query.get_or_404(id)
    if request.method == 'POST':
        asset.name = request.form['name']
        asset.asset_type = request.form['asset_type']
        asset.category = request.form['category']
        asset.description = request.form.get('description', '')
        asset.owner = request.form.get('owner', 'Unassigned')
        asset.location = request.form.get('location', '')
        asset.ip_address = request.form.get('ip_address', '')
        asset.criticality = request.form['criticality']
        asset.status = request.form.get('status', 'Active')
        asset.os_firmware = request.form.get('os_firmware', '')
        asset.vendor = request.form.get('vendor', '')
        db.session.commit()
        log_action('Updated', 'Asset', asset.id, asset.name, 'Asset details updated')
        flash(f'Asset "{asset.name}" updated successfully!', 'success')
        return redirect(url_for('asset_detail', id=asset.id))
    return render_template('asset_form.html', asset=asset, action='Edit')


@app.route('/assets/<int:id>/delete', methods=['POST'])
def asset_delete(id):
    """Delete an asset."""
    asset = Asset.query.get_or_404(id)
    name = asset.name
    db.session.delete(asset)
    db.session.commit()
    log_action('Deleted', 'Asset', id, name, 'Asset removed from registry')
    flash(f'Asset "{name}" deleted.', 'warning')
    return redirect(url_for('assets_list'))


# ═══════════════════════════════════════════════════════════
#  RISK MANAGEMENT
# ═══════════════════════════════════════════════════════════
@app.route('/risks')
def risks_list():
    """List all risks with filtering."""
    level = request.args.get('level', '')
    status = request.args.get('status', '')
    category = request.args.get('category', '')
    search = request.args.get('search', '')

    query = Risk.query
    if level:
        query = query.filter_by(risk_level=level)
    if status:
        query = query.filter_by(status=status)
    if category:
        query = query.filter_by(risk_category=category)
    if search:
        query = query.filter(Risk.title.contains(search) | Risk.description.contains(search))

    risks = query.order_by(Risk.risk_score.desc()).all()
    return render_template('risks.html', risks=risks,
                           filter_level=level, filter_status=status,
                           filter_category=category, search=search)


@app.route('/risks/add', methods=['GET', 'POST'])
def risk_add():
    """Add a new risk."""
    if request.method == 'POST':
        risk = Risk(
            title=request.form['title'],
            description=request.form.get('description', ''),
            risk_category=request.form['risk_category'],
            likelihood=int(request.form['likelihood']),
            impact=int(request.form['impact']),
            threat_source=request.form.get('threat_source', ''),
            affected_cia=request.form.get('affected_cia', ''),
            status=request.form.get('status', 'Open'),
            treatment=request.form.get('treatment', 'Mitigate'),
            risk_owner=request.form.get('risk_owner', 'Unassigned'),
            asset_id=int(request.form['asset_id']),
        )
        risk.calculate_risk()
        db.session.add(risk)
        db.session.commit()
        log_action('Created', 'Risk', risk.id, risk.title,
                   f'Risk score: {risk.risk_score} ({risk.risk_level})')
        flash(f'Risk "{risk.title}" created with score {risk.risk_score} ({risk.risk_level}).', 'success')
        return redirect(url_for('risks_list'))
    assets = Asset.query.filter_by(status='Active').order_by(Asset.name).all()
    return render_template('risk_form.html', risk=None, assets=assets, action='Add')


@app.route('/risks/<int:id>')
def risk_detail(id):
    """View risk details."""
    risk = Risk.query.get_or_404(id)
    return render_template('risk_detail.html', risk=risk)


@app.route('/risks/<int:id>/edit', methods=['GET', 'POST'])
def risk_edit(id):
    """Edit an existing risk."""
    risk = Risk.query.get_or_404(id)
    if request.method == 'POST':
        risk.title = request.form['title']
        risk.description = request.form.get('description', '')
        risk.risk_category = request.form['risk_category']
        risk.likelihood = int(request.form['likelihood'])
        risk.impact = int(request.form['impact'])
        risk.threat_source = request.form.get('threat_source', '')
        risk.affected_cia = request.form.get('affected_cia', '')
        risk.status = request.form.get('status', 'Open')
        risk.treatment = request.form.get('treatment', 'Mitigate')
        risk.risk_owner = request.form.get('risk_owner', 'Unassigned')
        risk.asset_id = int(request.form['asset_id'])
        risk.calculate_risk()
        risk.last_reviewed = datetime.now(timezone.utc)
        db.session.commit()
        log_action('Updated', 'Risk', risk.id, risk.title,
                   f'Updated risk score: {risk.risk_score} ({risk.risk_level})')
        flash(f'Risk "{risk.title}" updated.', 'success')
        return redirect(url_for('risk_detail', id=risk.id))
    assets = Asset.query.filter_by(status='Active').order_by(Asset.name).all()
    return render_template('risk_form.html', risk=risk, assets=assets, action='Edit')


@app.route('/risks/<int:id>/delete', methods=['POST'])
def risk_delete(id):
    """Delete a risk."""
    risk = Risk.query.get_or_404(id)
    title = risk.title
    db.session.delete(risk)
    db.session.commit()
    log_action('Deleted', 'Risk', id, title, 'Risk removed')
    flash(f'Risk "{title}" deleted.', 'warning')
    return redirect(url_for('risks_list'))


# ═══════════════════════════════════════════════════════════
#  RISK MATRIX
# ═══════════════════════════════════════════════════════════
@app.route('/risk-matrix')
def risk_matrix():
    """Interactive 5x5 risk assessment matrix."""
    risks = Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).all()
    matrix = {}
    for risk in risks:
        key = f"{risk.likelihood}-{risk.impact}"
        if key not in matrix:
            matrix[key] = []
        matrix[key].append({
            'id': risk.id, 'title': risk.title,
            'risk_level': risk.risk_level, 'asset': risk.asset.name
        })
    return render_template('risk_matrix.html', risks=risks, matrix=matrix)


# ═══════════════════════════════════════════════════════════
#  VULNERABILITIES
# ═══════════════════════════════════════════════════════════
@app.route('/vulnerabilities')
def vulnerabilities_list():
    """List all vulnerabilities."""
    severity = request.args.get('severity', '')
    query = Vulnerability.query
    if severity:
        query = query.filter_by(severity=severity)
    vulns = query.order_by(Vulnerability.cvss_score.desc()).all()
    return render_template('vulnerabilities.html', vulns=vulns, filter_severity=severity)


# ═══════════════════════════════════════════════════════════
#  MITIGATIONS
# ═══════════════════════════════════════════════════════════
@app.route('/mitigations')
def mitigations_list():
    """List all mitigations."""
    mitigations = Mitigation.query.order_by(Mitigation.created_at.desc()).all()
    return render_template('mitigations.html', mitigations=mitigations)


@app.route('/mitigations/add', methods=['GET', 'POST'])
def mitigation_add():
    """Add a mitigation to a risk."""
    if request.method == 'POST':
        mit = Mitigation(
            title=request.form['title'],
            description=request.form.get('description', ''),
            action_type=request.form.get('action_type', 'Technical'),
            status=request.form.get('status', 'Planned'),
            priority=request.form.get('priority', 'Medium'),
            assigned_to=request.form.get('assigned_to', 'Unassigned'),
            effectiveness=int(request.form.get('effectiveness', 0)),
            risk_id=int(request.form['risk_id']),
        )
        db.session.add(mit)
        db.session.commit()
        log_action('Created', 'Mitigation', mit.id, mit.title,
                   f'Mitigation for risk ID {mit.risk_id}')
        flash(f'Mitigation "{mit.title}" created.', 'success')
        return redirect(url_for('mitigations_list'))
    risks = Risk.query.filter(Risk.status.in_(['Open', 'In Progress'])).order_by(Risk.title).all()
    return render_template('mitigation_form.html', mitigation=None, risks=risks, action='Add')


# ═══════════════════════════════════════════════════════════
#  AUDIT LOG
# ═══════════════════════════════════════════════════════════
@app.route('/audit-log')
def audit_log():
    """View system audit trail."""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_log.html', logs=logs)


# ═══════════════════════════════════════════════════════════
#  API ENDPOINTS (for charts)
# ═══════════════════════════════════════════════════════════
@app.route('/api/risk-trend')
def api_risk_trend():
    """Return risk data for trend chart."""
    risks = Risk.query.all()
    data = {
        'levels': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
        'categories': {},
        'treatments': {'Mitigate': 0, 'Accept': 0, 'Transfer': 0, 'Avoid': 0},
    }
    for r in risks:
        if r.status in ('Open', 'In Progress'):
            data['levels'][r.risk_level] = data['levels'].get(r.risk_level, 0) + 1
            data['categories'][r.risk_category] = data['categories'].get(r.risk_category, 0) + 1
            data['treatments'][r.treatment] = data['treatments'].get(r.treatment, 0) + 1
    return jsonify(data)


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("\n" + "="*62)
    print("  Cyber IT/OT Risk Assessment Engine")
    print("  Starting on http://127.0.0.1:5000")
    print("="*62 + "\n")
    app.run(debug=True, port=5000)
