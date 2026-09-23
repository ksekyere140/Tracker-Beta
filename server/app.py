from flask import Flask, request, jsonify
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import getpass
import sqlite3


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "data" / "tracker.db"


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
        connection.execute("""
            INSERT INTO web_visits (
                timestamp,
                username,
                url,
                domain,
                browser
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            timestamp,
            username,
            url,
            domain,
            browser
        ))

    return jsonify({
        "status": "logged",
        "timestamp": timestamp,
        "username": username,
        "domain": domain,
        "url": url
    }), 201


if __name__ == "__main__":
    initialize_database()

    app.run(
        host="127.0.0.1",
        port=8765,
        debug=True
    )

