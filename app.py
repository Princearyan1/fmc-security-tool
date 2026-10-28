
import json

from services.ai_investigator import run_ai_investigation

import hashlib
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import (
    Flask, flash, redirect,
    render_template, request, url_for
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

from services.log_parser import parse_log_file

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY", "local-development-only"
)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///fmc_security.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

db = SQLAlchemy(app)

SOURCE_TYPES = [
    "SIEM", "Windows", "Linux",
    "EDR", "Firewall", "VPN", "MFA", "Other"
]

STATUSES = [
    "Open",
    "Investigating",
    "Awaiting Evidence",
    "Ready for Review",
    "Closed"
]


def current_time():
    return datetime.now(timezone.utc)


# ==========================================
# DATABASE MODELS
# ==========================================

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(
        db.String(254),
        unique=True,
        nullable=False,
        index=True
    )

    cases = db.relationship(
        "SecurityCase",
        back_populates="employee"
    )


class SecurityCase(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    employee_id = db.Column(
        db.Integer,
        db.ForeignKey("employee.id"),
        nullable=False,
        index=True
    )

    alert_name = db.Column(
        db.String(200),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        default="Medium",
        nullable=False
    )

    status = db.Column(
        db.String(30),
        default="Open",
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=current_time
    )

    employee = db.relationship(
        "Employee",
        back_populates="cases"
    )

    uploads = db.relationship(
        "EvidenceUpload",
        back_populates="case",
        cascade="all, delete-orphan"
    )

    events = db.relationship(
        "SecurityEvent",
        back_populates="case",
        cascade="all, delete-orphan"
    )


class EvidenceUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("security_case.id"),
        nullable=False,
        index=True
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    source_type = db.Column(
        db.String(30),
        nullable=False
    )

    sha256 = db.Column(
        db.String(64),
        nullable=False
    )

    imported_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    skipped_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    uploaded_at = db.Column(
        db.DateTime(timezone=True),
        default=current_time
    )

    case = db.relationship(
        "SecurityCase",
        back_populates="uploads"
    )

    events = db.relationship(
        "SecurityEvent",
        back_populates="upload"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "case_id", "sha256",
            name="unique_file_per_case"
        ),
    )


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("security_case.id"),
        nullable=False,
        index=True
    )

    upload_id = db.Column(
        db.Integer,
        db.ForeignKey("evidence_upload.id"),
        nullable=False,
        index=True
    )

    timestamp = db.Column(db.String(80))
    user_email = db.Column(db.String(254))
    source_ip = db.Column(db.String(100))
    device = db.Column(db.String(160))
    event_type = db.Column(db.String(200))
    outcome = db.Column(db.String(100))
    mfa_status = db.Column(db.String(120))
    vpn_status = db.Column(db.String(120))
    message = db.Column(db.Text)
    raw_payload = db.Column(db.Text)

    match_status = db.Column(
        db.String(30),
        nullable=False
    )

    case = db.relationship(
        "SecurityCase",
        back_populates="events"
    )

    upload = db.relationship(
        "EvidenceUpload",
        back_populates="events"
    )


# ==========================================
# AI INVESTIGATION REPORT MODEL
# ==========================================

class InvestigationReport(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    case_id = db.Column(
        db.Integer,
        db.ForeignKey("security_case.id"),
        nullable=False,
        index=True
    )

    model_name = db.Column(
        db.String(100),
        nullable=False
    )

    report_json = db.Column(
        db.Text,
        nullable=False
    )

    total_event_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=current_time
    )

# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    email_search = request.args.get(
        "email", ""
    ).strip().lower()

    query = SecurityCase.query

    if email_search:
        query = query.join(Employee).filter(
            Employee.email.contains(email_search)
        )

    cases = query.order_by(
        SecurityCase.created_at.desc(),
        SecurityCase.id.desc()
    ).all()

    stats = {
        "total": SecurityCase.query.count(),

        "active": SecurityCase.query.filter(
            SecurityCase.status != "Closed"
        ).count(),

        "critical": SecurityCase.query.filter(
            SecurityCase.severity.in_(["High", "Critical"]),
            SecurityCase.status != "Closed"
        ).count(),

        "employees": Employee.query.count()
    }

    return render_template(
        "dashboard.html",
        cases=cases,
        stats=stats,
        email_search=email_search
    )


# ==========================================
# CREATE CASE
# ==========================================

@app.route(
    "/cases/create",
    methods=["POST"]
)
def create_case():

    email = request.form.get(
        "email", ""
    ).strip().lower()

    alert_name = request.form.get(
        "alert_name", ""
    ).strip()

    severity = request.form.get(
        "severity", "Medium"
    )

    if (
        not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        )
        or len(email) > 254
        or not alert_name
        or len(alert_name) > 200
        or severity not in [
            "Low", "Medium", "High", "Critical"
        ]
    ):
        flash(
            "Please enter valid case details.",
            "error"
        )
        return redirect(url_for("dashboard"))

    employee = Employee.query.filter_by(
        email=email
    ).first()

    if employee is None:
        employee = Employee(email=email)
        db.session.add(employee)
        db.session.flush()

    case = SecurityCase(
        employee_id=employee.id,
        alert_name=alert_name,
        severity=severity
    )

    db.session.add(case)
    db.session.commit()

    flash(
        "Investigation case created.",
        "success"
    )

    return redirect(
        url_for(
            "case_detail",
            case_id=case.id
        )
    )


# ==========================================
# CASE DETAILS + HISTORICAL COMPARISON
# ==========================================

@app.route("/cases/<int:case_id>")
def case_detail(case_id):

    case = db.get_or_404(
        SecurityCase,
        case_id
    )

    previous_cases = SecurityCase.query.filter(
        SecurityCase.employee_id == case.employee_id,
        SecurityCase.id < case.id
    ).order_by(
        SecurityCase.created_at.desc()
    ).limit(20).all()

    uploads = EvidenceUpload.query.filter_by(
        case_id=case.id
    ).order_by(
        EvidenceUpload.id.desc()
    ).all()

    events = SecurityEvent.query.filter_by(
        case_id=case.id
    ).order_by(
        SecurityEvent.id.desc()
    ).limit(200).all()

    event_count = SecurityEvent.query.filter_by(
        case_id=case.id
    ).count()

    verified_count = SecurityEvent.query.filter_by(
        case_id=case.id,
        match_status="Matched"
    ).count()

    # Only explicitly email-matched events are compared.
    current_verified = SecurityEvent.query.filter_by(
        case_id=case.id,
        match_status="Matched"
    ).all()

    historical_verified = []

    if previous_cases:
        historical_verified = SecurityEvent.query.filter(
            SecurityEvent.case_id.in_(
                [c.id for c in previous_cases]
            ),
            SecurityEvent.match_status == "Matched"
        ).all()

    current_ips = {
        e.source_ip
        for e in current_verified
        if e.source_ip
    }

    historical_ips = {
        e.source_ip
        for e in historical_verified
        if e.source_ip
    }

    current_devices = {
        e.device
        for e in current_verified
        if e.device
    }

    historical_devices = {
        e.device
        for e in historical_verified
        if e.device
    }

    comparison = {
        "has_ip_baseline": bool(historical_ips),

        "new_ips": sorted(
            current_ips - historical_ips
        ),

        "shared_ips": sorted(
            current_ips & historical_ips
        ),

        "has_device_baseline": bool(
            historical_devices
        ),

        "new_devices": sorted(
            current_devices - historical_devices
        ),

        "shared_devices": sorted(
            current_devices & historical_devices
        )
    }
    
    # Latest AI investigation for this case
    latest_report = InvestigationReport.query.filter_by(
        case_id=case.id
    ).order_by(
        InvestigationReport.id.desc()
    ).first()

    report_data = None
    report_stale = False

    if latest_report:
        report_data = json.loads(
            latest_report.report_json
        )

        report_stale = (
            event_count > latest_report.total_event_count
        )


    return render_template(
        "case_detail.html",
        case=case,
        previous_cases=previous_cases,
        source_types=SOURCE_TYPES,
        statuses=STATUSES,
        uploads=uploads,
        events=events,
        event_count=event_count,
        verified_count=verified_count,
        comparison=comparison,
        latest_report=latest_report,
        report_data=report_data,
        report_stale=report_stale
    )


# ==========================================
# CASE-WISE LOG UPLOAD
# ==========================================

@app.route(
    "/cases/<int:case_id>/upload",
    methods=["POST"]
)
def upload_logs(case_id):

    case = db.get_or_404(
        SecurityCase,
        case_id
    )

    log_file = request.files.get("log_file")

    source_type = request.form.get(
        "source_type", "Other"
    )

    if (
        source_type not in SOURCE_TYPES
        or log_file is None
        or not log_file.filename
    ):
        flash(
            "Choose a log file and its source.",
            "error"
        )

        return redirect(
            url_for(
                "case_detail",
                case_id=case_id
            )
        )

    filename = secure_filename(
        log_file.filename
    )[:255]

    if not filename:
        flash("Invalid filename.", "error")
        return redirect(
            url_for("case_detail", case_id=case_id)
        )

    contents = log_file.read()

    digest = hashlib.sha256(
        contents
    ).hexdigest()

    duplicate = EvidenceUpload.query.filter_by(
        case_id=case.id,
        sha256=digest
    ).first()

    if duplicate:
        flash(
            "This exact file was already uploaded "
            "to this case.",
            "error"
        )

        return redirect(
            url_for("case_detail", case_id=case_id)
        )

    try:
        records = parse_log_file(
            contents,
            filename
        )

    except ValueError as exc:
        flash(str(exc), "error")

        return redirect(
            url_for("case_detail", case_id=case_id)
        )

    accepted = []
    skipped = 0

    for record in records:

        email = record["user_email"]

        # Explicit other-employee events do not
        # belong in this employee case.
        if email and email != case.employee.email:
            skipped += 1
            continue

        record["match_status"] = (
            "Matched" if email else "Unverified"
        )

        accepted.append(record)

    if not accepted:
        flash(
            "No events can be linked to this employee. "
            "No changes saved.",
            "error"
        )

        return redirect(
            url_for("case_detail", case_id=case_id)
        )

    upload = EvidenceUpload(
        case_id=case.id,
        filename=filename,
        source_type=source_type,
        sha256=digest,
        imported_count=len(accepted),
        skipped_count=skipped
    )

    db.session.add(upload)
    db.session.flush()

    for record in accepted:
        db.session.add(
            SecurityEvent(
                case_id=case.id,
                upload_id=upload.id,
                **record
            )
        )

    db.session.commit()

    flash(
        f"Imported {len(accepted)} events. "
        f"Excluded {skipped} events with another email.",
        "success"
    )

    return redirect(
        url_for("case_detail", case_id=case_id)
    )


# ==========================================
# UPDATE INVESTIGATION STATUS
# ==========================================

@app.route(
    "/cases/<int:case_id>/status",
    methods=["POST"]
)
def update_status(case_id):

    case = db.get_or_404(
        SecurityCase,
        case_id
    )

    status = request.form.get("status")

    if status not in STATUSES:
        flash("Invalid case status.", "error")

    else:
        case.status = status
        db.session.commit()

        flash(
            "Case status updated.",
            "success"
        )

    return redirect(
        url_for("case_detail", case_id=case_id)
    )


# ==========================================
# UPLOAD SIZE ERROR
# ==========================================

@app.errorhandler(413)
def too_large(_error):

    flash(
        "File too large. Maximum upload size is 5 MB.",
        "error"
    )

    return redirect(
        request.referrer
        or url_for("dashboard")
    )


# ==========================================
# AI INVESTIGATION ROUTE
# ==========================================

@app.route(
    "/cases/<int:case_id>/investigate",
    methods=["POST"]
)
def investigate_case(case_id):

    case = db.get_or_404(
        SecurityCase,
        case_id
    )

    total_events = SecurityEvent.query.filter_by(
        case_id=case.id
    ).count()

    if total_events == 0:
        flash(
            "Upload security logs before AI investigation.",
            "error"
        )

        return redirect(
            url_for("case_detail", case_id=case.id)
        )

    # Latest current-case events.
    current_events = SecurityEvent.query.filter_by(
        case_id=case.id
    ).order_by(
        SecurityEvent.id.desc()
    ).limit(80).all()

    current_events.reverse()

    # Previous-case evidence belonging to
    # the same employee identity.
    historical_events = (
        SecurityEvent.query
        .join(
            SecurityCase,
            SecurityEvent.case_id == SecurityCase.id
        )
        .filter(
            SecurityCase.employee_id == case.employee_id,
            SecurityCase.id < case.id,
            SecurityEvent.match_status == "Matched"
        )
        .order_by(
            SecurityEvent.id.desc()
        )
        .limit(25)
        .all()
    )

    historical_events.reverse()

    try:
        result = run_ai_investigation(
            alert_name=case.alert_name,
            current_events=current_events,
            historical_events=historical_events,
            total_current_count=total_events
        )

    except ValueError as exc:
        flash(str(exc), "error")

        return redirect(
            url_for("case_detail", case_id=case.id)
        )

    except Exception as exc:
        app.logger.warning(
            "AI investigation failed: %s",
            type(exc).__name__
        )

        flash(
            "Groq investigation failed. Check API key, "
            "model access and network connection.",
            "error"
        )

        return redirect(
            url_for("case_detail", case_id=case.id)
        )

    new_report = InvestigationReport(
        case_id=case.id,
        model_name=result["model"],
        report_json=json.dumps(
            result,
            ensure_ascii=False
        ),
        total_event_count=total_events
    )

    db.session.add(new_report)

    # Keep analyst's closed cases unchanged.
    if case.status != "Closed":
        if result["missing_evidence"]:
            case.status = "Awaiting Evidence"
        else:
            case.status = "Ready for Review"

    db.session.commit()

    flash(
        "AI investigation completed. "
        "Review evidence and root cause hypothesis.",
        "success"
    )

    return redirect(
        url_for("case_detail", case_id=case.id)
    )

# ==========================================
# DATABASE INITIALIZATION
# ==========================================

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
