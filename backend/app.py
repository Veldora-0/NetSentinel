"""NetSentinel Flask Backend Application.

Main entry point for the NetSentinel REST API, real-time Socket.IO connection server,
packet capture lifecycle, rule-based intrusion detection, and unsupervised ML anomaly detection.
"""

import threading
import time
from typing import Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from config import Config, resolve_network_interface
from database import init_db
from capture import PacketCapture
from detector import TrafficDetector, SecurityEvent
from ml.detector import MLAnomalyDetector, MLAnomalyEvent

# Global server components
packet_capture: PacketCapture = None
detector: TrafficDetector = None
ml_detector: MLAnomalyDetector = None
metrics_thread: threading.Thread = None


def create_app(config_class=Config, start_capture: bool = True) -> Tuple[Flask, SocketIO]:
    """Application factory for NetSentinel Flask Backend."""
    global packet_capture, detector, ml_detector, metrics_thread

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable Cross-Origin Resource Sharing
    CORS(app, resources={r"/api/*": {"origins": "*"}, r"/socket.io/*": {"origins": "*"}})

    # Initialize Database
    init_db(app)

    # Initialize Flask-SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # 1. Initialize Rule-Based Intrusion Detection Engine
    detector = TrafficDetector(config=app.config.get("DETECTOR_THRESHOLDS"))
    app.detector = detector

    # Broadcast rule-based security events over Socket.IO
    def _on_security_event(event: SecurityEvent) -> None:
        try:
            socketio.emit("security_event", event.to_dict())
        except Exception:
            pass

    detector.add_event_callback(_on_security_event)

    # 2. Initialize Machine Learning Anomaly Detector (Isolation Forest)
    ml_detector = MLAnomalyDetector(config=app.config.get("ML_SETTINGS"))
    app.ml_detector = ml_detector

    # Broadcast ML anomaly events over Socket.IO
    def _on_ml_anomaly(event: MLAnomalyEvent) -> None:
        try:
            socketio.emit("ml_anomaly", event.to_dict())
        except Exception:
            pass

    ml_detector.add_anomaly_callback(_on_ml_anomaly)

    # 3. Resolve network interface & initialize PacketCapture
    active_iface = resolve_network_interface(app.config.get("NETWORK_INTERFACE"))
    packet_capture = PacketCapture(interface=active_iface)
    app.packet_capture = packet_capture

    # Connect rule detector and ML detector as observers to the single raw packet stream
    packet_capture.add_packet_callback(detector.analyze_packet)
    packet_capture.add_packet_callback(ml_detector.process_packet)

    # Register API Routes
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint to verify backend operational status."""
        return jsonify({
            "status": "ok",
            "service": "NetSentinel Backend"
        }), 200

    @app.route("/api/metrics", methods=["GET"])
    def get_metrics():
        """REST endpoint to retrieve current packet capture metrics snapshot."""
        return jsonify(packet_capture.get_metrics()), 200

    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        """REST endpoint to retrieve recent security detection alerts (newest first)."""
        limit = request.args.get("limit", 50, type=int)
        alerts = detector.get_recent_alerts(limit=limit)
        return jsonify({
            "status": "ok",
            "count": len(alerts),
            "alerts": alerts,
        }), 200

    @app.route("/api/ml/status", methods=["GET"])
    def get_ml_status():
        """REST endpoint to retrieve ML anomaly detection model status."""
        return jsonify(ml_detector.get_status()), 200

    @app.route("/api/ml/metrics", methods=["GET"])
    def get_ml_metrics():
        """REST endpoint to retrieve ML window history and recent anomalies."""
        return jsonify(ml_detector.get_metrics()), 200

    # Socket.IO Event Handlers
    @socketio.on("connect")
    def handle_connect():
        """Handle client Socket.IO connection."""
        emit("connection_response", {
            "status": "connected",
            "message": "Connected to NetSentinel Socket.IO Server"
        })
        # Provide immediate initial snapshot to newly connected dashboard
        emit("traffic_metrics", packet_capture.get_metrics())
        emit("ml_status", ml_detector.get_status())

    @socketio.on("disconnect")
    def handle_disconnect():
        """Handle client Socket.IO disconnection."""
        pass

    @socketio.on("ping_server")
    def handle_ping(data):
        """Handle optional client ping test."""
        emit("pong_client", {"response": "pong", "received": data})

    # Start live capture, ML worker, and metrics emitter if requested and not in testing mode
    is_testing = app.config.get("TESTING", False)
    if start_capture and not is_testing:
        packet_capture.start()
        ml_detector.start()

        def _metrics_emitter():
            interval = app.config.get("METRICS_EMIT_INTERVAL", 1.0)
            while True:
                time.sleep(interval)
                try:
                    metrics = packet_capture.get_metrics()
                    socketio.emit("traffic_metrics", metrics)
                except Exception:
                    pass

        if metrics_thread is None or not metrics_thread.is_alive():
            metrics_thread = threading.Thread(
                target=_metrics_emitter, name="NetSentinel-MetricsEmitter", daemon=True
            )
            metrics_thread.start()

    return app, socketio


app, socketio = create_app()

if __name__ == "__main__":
    config = Config()
    print(f"Starting NetSentinel Backend Server on {config.HOST}:{config.PORT}...")
    try:
        socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG)
    finally:
        if packet_capture:
            packet_capture.stop()
        if ml_detector:
            ml_detector.stop()
