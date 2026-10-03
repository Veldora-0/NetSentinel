"""NetSentinel Database Module.

Establishes SQLite configuration and SQLAlchemy database instance foundation
for future security event and telemetry persistence.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """Initialize SQLAlchemy with the Flask application context."""
    db.init_app(app)
    with app.app_context():
        # Future tables will be created here via db.create_all()
        db.create_all()
