"""NetSentinel Flask Backend Application.

Main entry point for the NetSentinel REST API, real-time Socket.IO connection server,
packet capture lifecycle, rule-based intrusion detection, unsupervised ML anomaly detection,
composite risk scoring, and automated iptables firewall mitigation.
"""

import threading
import time
from typing import Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from config import Config, resolve_network_interface
from database import init_db, save_assessment_record
from capture import PacketCapture
from detector import TrafficDetector, SecurityEvent
from ml.detector import MLAnomalyDetector, MLAnomalyEvent
from risk_engine import RiskEngine, RiskAssessment
from firewall import FirewallManager

# Global server components
packet_capture: PacketCapture = None
detector: TrafficDetector = None
ml_detector: MLAnomalyDetector = None
risk_engine: RiskEngine = None
firewall: FirewallManager = None
metrics_thread: threading.Thread = None


def create_app(config_class=Config, start_capture: bool = True) -> Tuple[Flask, SocketIO]:
    """Application factory for NetSentinel Flask Backend."""
    global packet_capture, detector, ml_detector, risk_engine, firewall, metrics_thread

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

    # 2. Initialize Machine Learning Anomaly Detector (Isolation Forest)
    ml_detector = MLAnomalyDetector(config=app.config.get("ML_SETTINGS"))
    app.ml_detector = ml_detector

    # 3. Initialize Composite Risk Engine
    risk_engine = RiskEngine(config=app.config.get("RISK_SETTINGS"))
    app.risk_engine = risk_engine

    # 4. Initialize Linux iptables Firewall Manager
    firewall = FirewallManager(config=app.config.get("FIREWALL_SETTINGS"))
    app.firewall = firewall

    # Connect rule detector security events to Socket.IO and Risk Engine
    def _on_security_event(event: SecurityEvent) -> None:
        try:
            socketio.emit("security_event", event.to_dict())
        except Exception:
            pass

        # Phase 5: Pipeline: SecurityEvent -> RiskEngine -> Assessment -> Firewall
        try:
            with app.app_context():
                ml_status = ml_detector.get_status() if ml_detector else {}
                ml_score = ml_status.get("latest_anomaly_score", 0.0)

                assessment = risk_engine.assess(
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    rule_alerts=[event],
                    ml_anomaly_score=ml_score,
                )

                # Automated firewall mitigation if conditions are met
                if (
                    assessment.recommended_action == "block"
                    and firewall.auto_block
                    and firewall.enabled
                ):
                    block_res = firewall.block_ip(
                        ip_address=event.source_ip,
                        reason=f"Auto Block: Risk {assessment.combined_score:.2f} ({assessment.risk_level})",
                        duration=firewall.block_duration,
                        risk_score=assessment.combined_score,
                        assessment_id=assessment.assessment_id,
                    )
                    if block_res.get("success"):
                        assessment.blocked = True
                        risk_engine.mark_blocked(assessment.assessment_id, True)
                        socketio.emit("firewall_action", {
                            "timestamp": time.time(),
                            "action": "block",
                            "source_ip": event.source_ip,
                            "success": True,
                            "expires_at": block_res.get("expires_at"),
                            "reason": block_res.get("message"),
                        })

                # Persist assessment record to database
                save_assessment_record(
                    assessment,
                    actual_action="BLOCK" if assessment.blocked else "NONE",
                    block_expires_at=(time.time() + firewall.block_duration) if assessment.blocked else None,
                )

                # Emit real-time risk assessment over Socket.IO
                socketio.emit("risk_assessment", assessment.to_dict())

        except Exception as ex:
            app.logger.debug("Error in risk assessment pipeline: %s", ex)

    detector.add_event_callback(_on_security_event)

    # Broadcast ML anomaly events over Socket.IO
    def _on_ml_anomaly(event: MLAnomalyEvent) -> None:
        try:
            socketio.emit("ml_anomaly", event.to_dict())
        except Exception:
            pass

    ml_detector.add_anomaly_callback(_on_ml_anomaly)

    # 5. Resolve network interface & initialize PacketCapture
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

    # Phase 5: Risk Engine & Firewall Endpoints
    @app.route("/api/risk/recent", methods=["GET"])
    def get_recent_risks():
        """REST endpoint to retrieve recent risk assessments (newest first)."""
        limit = request.args.get("limit", 50, type=int)
        assessments = risk_engine.get_recent_assessments(limit=limit)
        return jsonify({
            "status": "ok",
            "count": len(assessments),
            "assessments": assessments,
        }), 200

    @app.route("/api/risk/stats", methods=["GET"])
    def get_risk_stats():
        """REST endpoint to retrieve composite risk statistics."""
        return jsonify({
            "status": "ok",
            "stats": risk_engine.get_stats(),
        }), 200

    @app.route("/api/firewall/status", methods=["GET"])
    def get_firewall_status():
        """REST endpoint to retrieve firewall integration and safety status."""
        return jsonify({
            "status": "ok",
            "firewall": firewall.get_status(),
        }), 200

    @app.route("/api/firewall/blocked", methods=["GET"])
    def get_blocked_ips():
        """REST endpoint to retrieve list of currently blocked IPs."""
        blocked = firewall.list_blocked_ips()
        return jsonify({
            "status": "ok",
            "count": len(blocked),
            "blocked_ips": blocked,
        }), 200

    @app.route("/api/firewall/block", methods=["POST"])
    def manual_block_ip():
        """REST endpoint to manually block a specific IP address on the managed chain."""
        data = request.get_json(silent=True) or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' field"}), 400

        reason = data.get("reason", "Operator Manual Block")
        duration = data.get("duration", None)
        if duration is not None:
            try:
                duration = float(duration)
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid 'duration' parameter"}), 400

        result = firewall.block_ip(ip_address=ip, reason=reason, duration=duration)
        if result.get("success"):
            socketio.emit("firewall_action", {
                "timestamp": time.time(),
                "action": "block",
                "source_ip": ip,
                "success": True,
                "expires_at": result.get("expires_at"),
                "reason": reason,
            })
            return jsonify({"status": "ok", "result": result}), 200
        else:
            return jsonify({"status": "error", "result": result}), 400

    @app.route("/api/firewall/unblock", methods=["POST"])
    def manual_unblock_ip():
        """REST endpoint to manually unblock an IP address from the managed chain."""
        data = request.get_json(silent=True) or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' field"}), 400

        result = firewall.unblock_ip(ip_address=ip)
        if result.get("success"):
            socketio.emit("firewall_action", {
                "timestamp": time.time(),
                "action": "unblock",
                "source_ip": ip,
                "success": True,
                "expires_at": None,
                "reason": "Operator Manual Unblock",
            })
            return jsonify({"status": "ok", "result": result}), 200
        else:
            return jsonify({"status": "error", "result": result}), 400

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
        emit("risk_status", risk_engine.get_stats())
        emit("firewall_status", firewall.get_status())
        emit("blocked_ips", firewall.list_blocked_ips())

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
