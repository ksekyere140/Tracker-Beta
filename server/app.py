from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, session
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
import getpass
import sqlite3
import csv
import io
import hashlib
import json
from functools import wraps
from werkzeug.security import check_password_hash

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "data" / "tracker.db"

AUTH_CONFIG_PATH = BASE_DIR / "data" / "auth_config.json"


def load_auth_config():
    with open(AUTH_CONFIG_PATH, "r") as file:
        return json.load(file)


AUTH_CONFIG = load_auth_config()

app.secret_key = AUTH_CONFIG["secret_key"]

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

def calculate_event_hash(
    timestamp,
    username,
    url,
    domain,
    browser,
    severity,
    reason,
    previous_hash
):
    event_data = "|".join([
        timestamp,
        username,
        url,
        domain,
        browser,
        severity,
        reason or "",
        previous_hash or "GENESIS"
    ])

    return hashlib.sha256(
        event_data.encode("utf-8")
    ).hexdigest()
    return hashlib.sha256(
        event_data.encode("utf-8")
    ).hexdigest()
def verify_hash_chain():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT
                id,
                timestamp,
                username,
                url,
                domain,
                browser,
                severity,
                reason,
                previous_hash,
                event_hash
            FROM web_visits
            WHERE event_hash IS NOT NULL
            ORDER BY id ASC
        """).fetchall()

    if not rows:
        return True, "No hashed events recorded yet", 0

    expected_previous_hash = "GENESIS"

    for row in rows:

        if row["previous_hash"] != expected_previous_hash:
            return (
                False,
                f"Broken chain link at event {row['id']}",
                len(rows)
            )

        calculated_hash = calculate_event_hash(
            row["timestamp"],
            row["username"],
            row["url"],
            row["domain"],
            row["browser"],
            row["severity"],
            row["reason"],
            row["previous_hash"]
        )

        if row["event_hash"] != calculated_hash:
            return (
                False,
                f"Modified data detected at event {row['id']}",
                len(rows)
            )

        expected_previous_hash = row["event_hash"]

    return True, "Hash chain verified", len(rows)
def login_required(route_function):
    @wraps(route_function)
    def wrapped_route(*args, **kwargs):

        if not session.get("authenticated"):
            return redirect(url_for("login"))

        return route_function(*args, **kwargs)

    return wrapped_route

def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS web_visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                browser TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS domain_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT
            )
        """)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "application": "Tracker Beta",
        "status": "online"
    })


@app.route("/visit", methods=["POST"])
def log_visit():
    data = request.get_json(silent=True) or {}

    url = data.get("url")
    browser = data.get("browser", "Unknown")

    if not url:
        return jsonify({
            "error": "URL is required"
        }), 400

    domain = urlparse(url).netloc
    username = getpass.getuser()
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    with sqlite3.connect(DATABASE_PATH) as connection:

        watch_entry = connection.execute("""
            SELECT severity, reason
            FROM domain_watchlist
            WHERE domain = ?
        """, (domain,)).fetchone()

        if watch_entry:
            severity = watch_entry[0]
            reason = watch_entry[1]
        else:
            severity = "Normal"
            reason = None
        previous_row = connection.execute("""
            SELECT event_hash
            FROM web_visits
            WHERE event_hash IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        if previous_row:
            previous_hash = previous_row[0]
        else:
            previous_hash = "GENESIS"

        event_hash = calculate_event_hash(
            timestamp,
            username,
            url,
            domain,
            browser,
            severity,
            reason,
            previous_hash
        )

        connection.execute("""
            INSERT INTO web_visits (
                timestamp,
                username,
                url,
                domain,
                browser,
                severity,
                reason,
                previous_hash,
                event_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            username,
            url,
            domain,
            browser,
            severity,
            reason,
            previous_hash,
            event_hash
        ))
    return jsonify({
        "status": "logged",
        "timestamp": timestamp,
        "username": username,
        "domain": domain,
        "url": url,
        "severity": severity,
        "reason": reason
    }), 201
@app.route("/watchlist/add", methods=["POST"])
@login_required
def add_watchlist_domain():
    domain = request.form.get("domain", "").strip().lower()
    severity = request.form.get("severity", "Watch").strip()
    reason = request.form.get("reason", "").strip()

    if not domain:
        return redirect(url_for("dashboard"))

    if severity not in ("Watch", "Flagged"):
        severity = "Watch"

    if "://" in domain:
        domain = urlparse(domain).netloc
    else:
        domain = domain.split("/")[0]

    domain = domain.split(":")[0]

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            INSERT INTO domain_watchlist (
                domain,
                severity,
                reason
            )
            VALUES (?, ?, ?)
            ON CONFLICT(domain)
            DO UPDATE SET
                severity = excluded.severity,
                reason = excluded.reason
        """, (
            domain,
            severity,
            reason
        ))

    return redirect(url_for("dashboard"))
@app.route("/watchlist/remove", methods=["POST"])
@login_required
def remove_watchlist_domain():
    domain = request.form.get("domain", "").strip().lower()

    if domain:
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.execute("""
                DELETE FROM domain_watchlist
                WHERE domain = ?
            """, (domain,))

    return redirect(url_for("dashboard"))
@app.route("/export/security.csv", methods=["GET"])
@login_required
def export_security_csv():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row

        security_events = connection.execute("""
            SELECT
                v.timestamp,
                v.username,
                v.domain,
                v.browser,
                v.url,
                w.severity,
                w.reason
            FROM web_visits AS v
            INNER JOIN domain_watchlist AS w
                ON v.domain = w.domain
            WHERE w.severity IN ('Watch', 'Flagged')
            ORDER BY v.id DESC
        """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Timestamp",
        "User",
        "Domain",
        "Browser",
        "URL",
        "Severity",
        "Reason"
    ])

    for event in security_events:
        writer.writerow([
            event["timestamp"],
            event["username"],
            event["domain"],
            event["browser"],
            event["url"],
            event["severity"],
            event["reason"] or ""
        ])

    csv_data = output.getvalue()
    output.close()

    filename_time = datetime.now().strftime("%Y%m%d-%H%M%S")

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="tracker-beta-security-{filename_time}.csv"'
        }
    )
@app.route("/integrity/verify", methods=["GET"])
@login_required
def manual_integrity_verify():
    integrity_verified, integrity_message, hashed_event_count = verify_hash_chain()
    checked_at = datetime.now().astimezone().isoformat(timespec="seconds")

    return render_template(
        "integrity_result.html",
        integrity_verified=integrity_verified,
        integrity_message=integrity_message,
        hashed_event_count=hashed_event_count,
        checked_at=checked_at
    )
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        valid_username = username == AUTH_CONFIG["username"]

        valid_password = check_password_hash(
            AUTH_CONFIG["password_hash"],
            password
        )

        if valid_username and valid_password:
            session.clear()
            session["authenticated"] = True
            session["username"] = username

            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()

    return redirect(url_for("login"))    
@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    integrity_verified, integrity_message, hashed_event_count = verify_hash_chain()
    now = datetime.now().astimezone()

    today_start = now.replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0
    )

    tomorrow_start = today_start + timedelta(days=1)

    domain_filter = request.args.get("domain", "").strip()
    user_filter = request.args.get("user", "").strip()
    date_filter = request.args.get("date", "").strip()

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row

        total_visits = connection.execute("""
            SELECT COUNT(*)
            FROM web_visits
        """).fetchone()[0]

        visits_today = connection.execute("""
            SELECT COUNT(*)
            FROM web_visits
            WHERE timestamp >= ?
            AND timestamp < ?
        """, (
            today_start.isoformat(),
            tomorrow_start.isoformat()
        )).fetchone()[0]

        unique_domains = connection.execute("""
            SELECT COUNT(DISTINCT domain)
            FROM web_visits
        """).fetchone()[0]

        unique_users = connection.execute("""
            SELECT COUNT(DISTINCT username)
            FROM web_visits
        """).fetchone()[0]
        watch_events = connection.execute("""
            SELECT COUNT(*)
            FROM web_visits AS v
            INNER JOIN domain_watchlist AS w
                ON v.domain = w.domain
            WHERE w.severity = 'Watch'
        """).fetchone()[0]

        flagged_events = connection.execute("""
            SELECT COUNT(*)
            FROM web_visits AS v
            INNER JOIN domain_watchlist AS w
                ON v.domain = w.domain
            WHERE w.severity = 'Flagged'
        """).fetchone()[0]
        security_events = connection.execute("""
            SELECT
                v.timestamp,
                v.username,
                v.domain,
                v.browser,
                v.url,
                w.severity,
                w.reason
            FROM web_visits AS v
            INNER JOIN domain_watchlist AS w
                ON v.domain = w.domain
            WHERE w.severity IN ('Watch', 'Flagged')
            ORDER BY v.id DESC
            LIMIT 20
        """).fetchall()
        watchlist_entries = connection.execute("""
            SELECT
                domain,
                severity,
                reason
            FROM domain_watchlist
            ORDER BY
                CASE severity
                    WHEN 'Flagged' THEN 1
                    WHEN 'Watch' THEN 2
                    ELSE 3
                END,
                domain
        """).fetchall()

        top_domains = connection.execute("""
            SELECT
                domain,
                COUNT(*) AS visits
            FROM web_visits
            GROUP BY domain
            ORDER BY visits DESC
            LIMIT 10
        """).fetchall()

        hour_rows = connection.execute("""
            SELECT
                substr(timestamp, 12, 2) AS hour,
                COUNT(*) AS visits
            FROM web_visits
            WHERE timestamp >= ?
            AND timestamp < ?
            GROUP BY hour
            ORDER BY hour
        """, (
            today_start.isoformat(),
            tomorrow_start.isoformat()
        )).fetchall()

        hour_counts = {
            int(row["hour"]): row["visits"]
            for row in hour_rows
        }

        hourly_visits = []

        for hour in range(24):
            hourly_visits.append({
                "hour": f"{hour:02d}:00",
                "visits": hour_counts.get(hour, 0)
            })

        max_hourly_visits = max(
            [item["visits"] for item in hourly_visits],
            default=1
        )

        if max_hourly_visits == 0:
            max_hourly_visits = 1

        seven_days_start = today_start - timedelta(days=6)
        day_rows = connection.execute("""
            SELECT
                substr(timestamp, 1, 10) AS visit_date,
                COUNT(*) AS visits
            FROM web_visits
            WHERE timestamp >= ?
            AND timestamp < ?
            GROUP BY visit_date
            ORDER BY visit_date
        """, (
            seven_days_start.isoformat(),
            tomorrow_start.isoformat()
        )).fetchall()

        day_counts = {
            row["visit_date"]: row["visits"]
            for row in day_rows
        }

        seven_day_visits = []

        for days_ago in range(6, -1, -1):
            day = today_start - timedelta(days=days_ago)
            date_key = day.date().isoformat()

            seven_day_visits.append({
                "date": date_key,
                "label": day.strftime("%a %b %d"),
                "visits": day_counts.get(date_key, 0)
            })

        max_seven_day_visits = max(
            [item["visits"] for item in seven_day_visits],
            default=1
        )

        if max_seven_day_visits == 0:
            max_seven_day_visits = 1

        max_domain_visits = max(
            [item["visits"] for item in top_domains],
            default=1
        )

        if max_domain_visits == 0:
            max_domain_visits = 1

        conditions = []
        parameters = []

        if domain_filter:
            conditions.append("v.domain LIKE ?")
            parameters.append(f"%{domain_filter}%")

        if user_filter:
            conditions.append("v.username LIKE ?")
            parameters.append(f"%{user_filter}%")

        if date_filter:
            conditions.append("v.timestamp LIKE ?")
            parameters.append(f"{date_filter}%")

        where_clause = ""

        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        query = f"""
            SELECT
                v.timestamp,
                v.username,
                v.domain,
                v.browser,
                v.url,
                COALESCE(w.severity, 'Normal') AS severity,
                w.reason AS reason
            FROM web_visits AS v
            LEFT JOIN domain_watchlist AS w
                ON v.domain = w.domain
            {where_clause}
            ORDER BY v.id DESC
            LIMIT 100
        """
        recent_visits = connection.execute(
            query,
            parameters
        ).fetchall()

    return render_template(
        "dashboard.html",
        total_visits=total_visits,
        visits_today=visits_today,
        unique_domains=unique_domains,
        unique_users=unique_users,
        top_domains=top_domains,
        hourly_visits=hourly_visits,
        max_hourly_visits=max_hourly_visits,
        max_domain_visits=max_domain_visits,
	seven_day_visits=seven_day_visits,
	max_seven_day_visits=max_seven_day_visits,
        recent_visits=recent_visits,
        domain_filter=domain_filter,
        user_filter=user_filter,
        date_filter=date_filter,
        watch_events=watch_events,
        flagged_events=flagged_events,
	security_events=security_events,
	watchlist_entries=watchlist_entries,
        integrity_verified=integrity_verified,
        integrity_message=integrity_message,
        hashed_event_count=hashed_event_count,
    )
if __name__ == "__main__":
    initialize_database()

    app.run(
        host="127.0.0.1",
        port=8765,
        debug=False,
        use_reloader=False
    )








