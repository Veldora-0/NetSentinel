"""NetSentinel Flask Backend Application.

Main entry point for the NetSentinel REST API, real-time Socket.IO connection server,
packet capture lifecycle, rule-based intrusion detection, unsupervised ML anomaly detection,
composite risk scoring, automated iptables firewall mitigation, durable event persistence,
and host system telemetry sampling.
"""

import threading
import time
from typing import Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from config import Config, resolve_network_interface
from database import (
    init_db,
    save_assessment_record,
    save_security_event_record,
    save_firewall_action_record,
    save_incident_record,
    save_incident_evidence_record,
    get_incident_by_id,
    query_incidents,
    query_incident_stats,
    query_security_events,
    query_risk_history,
    query_security_summary,
    query_telemetry_history,
    cleanup_old_records,
)
from capture import PacketCapture
from detector import TrafficDetector, SecurityEvent
from ml.detector import MLAnomalyDetector, MLAnomalyEvent
from risk_engine import RiskEngine, RiskAssessment
from firewall import FirewallManager
from telemetry import TelemetryWorker
from host import HostDetectionManager
from arp_detector import ARPDetector
from incident_manager import IncidentManager

# Global server components
packet_capture: PacketCapture = None
detector: TrafficDetector = None
ml_detector: MLAnomalyDetector = None
risk_engine: RiskEngine = None
firewall: FirewallManager = None
telemetry_worker: TelemetryWorker = None
host_manager: HostDetectionManager = None
arp_detector: ARPDetector = None
incident_manager: IncidentManager = None
metrics_thread: threading.Thread = None


def create_app(config_class=Config, start_capture: bool = True) -> Tuple[Flask, SocketIO]:
    """Application factory for NetSentinel Flask Backend."""
    global packet_capture, detector, ml_detector, risk_engine, firewall, telemetry_worker, host_manager, arp_detector, incident_manager, metrics_thread


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

    # 5. Initialize Host Telemetry Worker (Phase 6)
    telemetry_worker = TelemetryWorker(
        app=app,
        socketio=socketio,
        config=app.config.get("TELEMETRY_SETTINGS"),
    )
    app.telemetry_worker = telemetry_worker

    # 6. Initialize Host-Based Intrusion Detection Manager (Phase 7)
    host_manager = HostDetectionManager(config=app.config.get("HOST_DETECTION_SETTINGS"))
    app.host_manager = host_manager

    # 7. Initialize Advanced ARP Threat Detector (Phase 8)
    arp_detector = ARPDetector(config=app.config.get("ARP_DETECTION_SETTINGS"))
    app.arp_detector = arp_detector

    # 8. Initialize Incident Manager (Phase 9)
    incident_manager = IncidentManager(
        config=app.config.get("INCIDENT_SETTINGS"),
        on_incident_created=lambda inc: socketio.emit("incident_created", inc),
        on_incident_updated=lambda inc: socketio.emit("incident_updated", inc),
        on_incident_status_changed=lambda data: socketio.emit("incident_status_changed", data),
    )
    app.incident_manager = incident_manager

    # Connect rule detector security events to persistence, Socket.IO, and Risk Engine
    def _on_security_event(event: SecurityEvent) -> None:
        try:
            socketio.emit("security_event", event.to_dict())
        except Exception:
            pass

        # Persist security event to SQLite
        try:
            with app.app_context():
                save_security_event_record(event)
        except Exception as ex:
            app.logger.debug("Error persisting security event: %s", ex)

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

                        save_firewall_action_record(
                            action="block",
                            source_ip=event.source_ip,
                            success=True,
                            reason=block_res.get("message", "Auto Block"),
                            risk_score=assessment.combined_score,
                            assessment_id=assessment.assessment_id,
                            expires_at=block_res.get("expires_at"),
                        )

                        socketio.emit("firewall_action", {
                            "timestamp": time.time(),
                            "action": "block",
                            "source_ip": event.source_ip,
                            "success": True,
                            "expires_at": block_res.get("expires_at"),
                            "reason": block_res.get("message"),
                        })

                        incident_manager.correlate_firewall_action(
                            action="block",
                            source_ip=event.source_ip,
                            reason=block_res.get("message", "Auto Block"),
                            duration=firewall.block_duration,
                            timestamp=time.time(),
                        )

                # Persist assessment record to database
                save_assessment_record(
                    assessment,
                    actual_action="BLOCK" if assessment.blocked else "NONE",
                    block_expires_at=(time.time() + firewall.block_duration) if assessment.blocked else None,
                )

                # Emit real-time risk assessment over Socket.IO
                socketio.emit("risk_assessment", assessment.to_dict())

                # Phase 9: Correlate into Incident
                incident_manager.correlate_security_event(event, risk_assessment=assessment)

        except Exception as ex:
            app.logger.debug("Error in risk assessment/incident pipeline: %s", ex)

    detector.add_event_callback(_on_security_event)

    # Broadcast and persist ML anomaly events
    def _on_ml_anomaly(event: MLAnomalyEvent) -> None:
        try:
            socketio.emit("ml_anomaly", event.to_dict())
        except Exception:
            pass

        try:
            with app.app_context():
                save_security_event_record(event)
                incident_manager.correlate_security_event(event)
        except Exception as ex:
            app.logger.debug("Error persisting ML anomaly: %s", ex)


    ml_detector.add_anomaly_callback(_on_ml_anomaly)

    # Connect host detector security events to persistence, Socket.IO, and Risk Engine
    def _on_host_security_event(event: SecurityEvent) -> None:
        try:
            socketio.emit("host_security_event", event.to_dict())
        except Exception:
            pass
        _on_security_event(event)

    host_manager.add_event_callback(_on_host_security_event)
    arp_detector.add_event_callback(_on_security_event)

    # 6. Resolve network interface & initialize PacketCapture
    active_iface = resolve_network_interface(app.config.get("NETWORK_INTERFACE"))
    packet_capture = PacketCapture(interface=active_iface)
    app.packet_capture = packet_capture

    # Connect rule detector, ML detector, and ARP detector as observers to the single raw packet stream
    packet_capture.add_packet_callback(detector.analyze_packet)
    packet_capture.add_packet_callback(ml_detector.process_packet)
    packet_capture.add_packet_callback(arp_detector.process_packet)

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
        """REST endpoint to retrieve recent in-memory security detection alerts (newest first)."""
        limit = request.args.get("limit", 50, type=int)
        alerts = detector.get_recent_alerts(limit=limit)
        return jsonify({
            "status": "ok",
            "count": len(alerts),
            "alerts": alerts,
        }), 200

    @app.route("/api/events", methods=["GET"])
    def get_security_events():
        """REST endpoint to retrieve persisted historical security events with filtering and pagination."""
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        since = request.args.get("since", None, type=float)
        until = request.args.get("until", None, type=float)
        source_ip = request.args.get("source_ip", None, type=str)
        detection_type = request.args.get("detection_type", None, type=str)
        severity = request.args.get("severity", None, type=str)

        result = query_security_events(
            limit=limit,
            offset=offset,
            since=since,
            until=until,
            source_ip=source_ip,
            detection_type=detection_type,
            severity=severity,
        )
        return jsonify({"status": "ok", **result}), 200

    @app.route("/api/ml/status", methods=["GET"])
    def get_ml_status():
        """REST endpoint to retrieve ML anomaly detection model status."""
        return jsonify(ml_detector.get_status()), 200

    @app.route("/api/ml/metrics", methods=["GET"])
    def get_ml_metrics():
        """REST endpoint to retrieve ML window history and recent anomalies."""
        return jsonify(ml_detector.get_metrics()), 200

    # Risk Engine & Firewall Endpoints
    @app.route("/api/risk/recent", methods=["GET"])
    def get_recent_risks():
        """REST endpoint to retrieve recent in-memory risk assessments (newest first)."""
        limit = request.args.get("limit", 50, type=int)
        assessments = risk_engine.get_recent_assessments(limit=limit)
        return jsonify({
            "status": "ok",
            "count": len(assessments),
            "assessments": assessments,
        }), 200

    @app.route("/api/risk/history", methods=["GET"])
    def get_risk_history():
        """REST endpoint to retrieve historical persisted risk assessments."""
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        since = request.args.get("since", None, type=float)
        until = request.args.get("until", None, type=float)
        source_ip = request.args.get("source_ip", None, type=str)
        risk_level = request.args.get("risk_level", None, type=str)

        result = query_risk_history(
            limit=limit,
            offset=offset,
            since=since,
            until=until,
            source_ip=source_ip,
            risk_level=risk_level,
        )
        return jsonify({"status": "ok", **result}), 200

    @app.route("/api/risk/stats", methods=["GET"])
    def get_risk_stats():
        """REST endpoint to retrieve composite risk statistics."""
        return jsonify({
            "status": "ok",
            "stats": risk_engine.get_stats(),
        }), 200

    @app.route("/api/security/summary", methods=["GET"])
    def get_security_summary():
        """REST endpoint to retrieve aggregate security metrics across events, risks, and mitigations."""
        since = request.args.get("since", None, type=float)
        summary = query_security_summary(since_timestamp=since)
        return jsonify({"status": "ok", "summary": summary}), 200

    # Host Telemetry Endpoints (Phase 6)
    @app.route("/api/telemetry/current", methods=["GET"])
    def get_current_telemetry():
        """REST endpoint to retrieve instantaneous host telemetry snapshot."""
        data = telemetry_worker.get_current_telemetry() if telemetry_worker else {}
        return jsonify({"status": "ok", "telemetry": data}), 200

    @app.route("/api/telemetry/history", methods=["GET"])
    def get_telemetry_history():
        """REST endpoint to retrieve bounded historical host telemetry records."""
        limit = request.args.get("limit", 60, type=int)
        since = request.args.get("since", None, type=float)
        until = request.args.get("until", None, type=float)
        result = query_telemetry_history(limit=limit, since=since, until=until)
        return jsonify({"status": "ok", **result}), 200

    # Host-Based Intrusion Detection Endpoints (Phase 7)
    @app.route("/api/host/status", methods=["GET"])
    def get_host_status():
        """REST endpoint to retrieve host detection status (SSH detector & Process monitor)."""
        status = host_manager.get_status() if host_manager else {}
        return jsonify({"status": "ok", "host": status, "data": status}), 200

    @app.route("/api/host/events", methods=["GET"])
    def get_host_events():
        """REST endpoint to retrieve persisted host security events with filtering and pagination."""
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        since = request.args.get("since", None, type=float)
        until = request.args.get("until", None, type=float)
        source_ip = request.args.get("source_ip", None, type=str)
        detection_type = request.args.get("detection_type", None, type=str)
        severity = request.args.get("severity", None, type=str)

        host_types = ["SSH_AUTH_FAILURE", "SSH_BRUTE_FORCE", "SUSPICIOUS_PROCESS"]
        if detection_type and detection_type.strip().upper() in host_types:
            result = query_security_events(
                limit=limit,
                offset=offset,
                since=since,
                until=until,
                source_ip=source_ip,
                detection_type=detection_type.strip().upper(),
                severity=severity,
            )
        else:
            from database import SecurityEventRecord
            query = SecurityEventRecord.query.filter(SecurityEventRecord.detection_type.in_(host_types))
            if since is not None:
                query = query.filter(SecurityEventRecord.timestamp >= since)
            if until is not None:
                query = query.filter(SecurityEventRecord.timestamp <= until)
            if source_ip and source_ip.strip():
                query = query.filter(SecurityEventRecord.source_ip == source_ip.strip())
            if severity and severity.strip():
                query = query.filter(SecurityEventRecord.severity == severity.strip().upper())

            total = query.count()
            records = (
                query.order_by(SecurityEventRecord.timestamp.desc())
                .offset(max(0, offset))
                .limit(max(1, min(limit, 500)))
                .all()
            )
            result = {
                "total": total,
                "count": len(records),
                "limit": limit,
                "offset": offset,
                "events": [r.to_dict() for r in records],
            }

        return jsonify({"status": "ok", **result}), 200

    # Advanced Network Threat Detection Endpoints (Phase 8)
    @app.route("/api/network/status", methods=["GET"])
    def get_network_status():
        """REST endpoint to retrieve network detection status (packet metrics, ARP status, ICMP sweep)."""
        metrics = packet_capture.get_metrics() if packet_capture else {}
        arp_status = arp_detector.get_status() if arp_detector else {}
        icmp_status = {
            "enabled": True,
            "window_sec": detector.icmp_sweep_window_sec if detector else 10.0,
            "threshold": detector.icmp_sweep_threshold if detector else 10,
            "cooldown_sec": detector.icmp_sweep_cooldown_sec if detector else 60.0,
            "tracked_sources": len(detector._icmp_sweep_state) if detector else 0,
        }
        thresholds = {
            "port_scan_threshold": detector.port_scan_threshold if detector else 15,
            "syn_flood_threshold": detector.syn_flood_threshold if detector else 50,
            "null_scan_enabled": detector.null_scan_enabled if detector else True,
            "xmas_scan_enabled": detector.xmas_scan_enabled if detector else True,
            "icmp_sweep_threshold": detector.icmp_sweep_threshold if detector else 10,
        }
        return jsonify({
            "status": "ok",
            "network": {
                "capture": metrics,
                "arp": arp_status,
                "icmp_sweep": icmp_status,
                "thresholds": thresholds,
            },
            "arp": arp_status,
            "icmp_sweep": icmp_status,
        }), 200

    @app.route("/api/network/arp", methods=["GET"])
    def get_arp_mappings():
        """REST endpoint to retrieve tracked ARP IP-to-MAC mappings."""
        limit = request.args.get("limit", 100, type=int)
        mappings = arp_detector.get_mappings(limit=limit) if arp_detector else []
        status = arp_detector.get_status() if arp_detector else {}
        return jsonify({
            "status": "ok",
            "total": status.get("tracked_ips_count", len(mappings)),
            "count": len(mappings),
            "mappings": mappings,
            "arp_status": status,
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
            try:
                with app.app_context():
                    save_firewall_action_record(
                        action="block",
                        source_ip=ip,
                        success=True,
                        reason=reason,
                        expires_at=result.get("expires_at"),
                    )
            except Exception as ex:
                app.logger.debug("Failed to persist manual block action: %s", ex)

            socketio.emit("firewall_action", {
                "timestamp": time.time(),
                "action": "block",
                "source_ip": ip,
                "success": True,
                "expires_at": result.get("expires_at"),
                "reason": reason,
            })

            incident_manager.correlate_firewall_action(
                action="block",
                source_ip=ip,
                reason=f"Operator Manual Block: {reason}",
                duration=duration,
                timestamp=time.time(),
            )
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
            try:
                with app.app_context():
                    save_firewall_action_record(
                        action="unblock",
                        source_ip=ip,
                        success=True,
                        reason="Operator Manual Unblock",
                    )
            except Exception as ex:
                app.logger.debug("Failed to persist manual unblock action: %s", ex)

            socketio.emit("firewall_action", {
                "timestamp": time.time(),
                "action": "unblock",
                "source_ip": ip,
                "success": True,
                "expires_at": None,
                "reason": "Operator Manual Unblock",
            })

            incident_manager.correlate_firewall_action(
                action="unblock",
                source_ip=ip,
                reason="Operator Manual Unblock",
                timestamp=time.time(),
            )
            return jsonify({"status": "ok", "result": result}), 200
        else:
            return jsonify({"status": "error", "result": result}), 400

    # ==========================================================================
    # Incident Correlation & Investigation Endpoints (Phase 9)
    # ==========================================================================
    @app.route("/api/incidents", methods=["GET"])
    def get_incidents():
        """Retrieve paginated and filtered security incidents."""
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        since = request.args.get("since", None, type=float)
        until = request.args.get("until", None, type=float)
        status = request.args.get("status", None, type=str)
        severity = request.args.get("severity", None, type=str)
        source_ip = request.args.get("source_ip", None, type=str) or request.args.get("primary_source_ip", None, type=str)
        correlation_key = request.args.get("correlation_key", None, type=str)

        result = query_incidents(
            limit=limit,
            offset=offset,
            since=since,
            until=until,
            status=status,
            severity=severity,
            primary_source_ip=source_ip,
            correlation_key=correlation_key,
        )
        return jsonify({"status": "ok", **result}), 200

    @app.route("/api/incidents/stats", methods=["GET"])
    def get_incident_stats():
        """Retrieve aggregated incident metrics (open/resolved counts, severity breakdown, top sources)."""
        since = request.args.get("since", None, type=float)
        stats = query_incident_stats(since_timestamp=since)
        return jsonify({"status": "ok", "stats": stats}), 200

    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    def get_incident_detail(incident_id: str):
        """Retrieve comprehensive incident record including correlated evidence items."""
        inc = incident_manager.get_incident(incident_id, include_evidence=True)
        if not inc:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
        return jsonify({"status": "ok", "incident": inc}), 200

    @app.route("/api/incidents/<incident_id>/timeline", methods=["GET"])
    def get_incident_timeline(incident_id: str):
        """Retrieve unified chronological timeline of all events and mitigation actions."""
        inc = incident_manager.get_incident(incident_id, include_evidence=False)
        if not inc:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
        timeline = incident_manager.build_incident_timeline(incident_id)
        return jsonify({
            "status": "ok",
            "incident_id": incident_id,
            "count": len(timeline),
            "timeline": timeline,
        }), 200

    @app.route("/api/incidents/<incident_id>/summary", methods=["GET"])
    def get_incident_summary_report(incident_id: str):
        """Retrieve SOC-ready report summary for an incident."""
        summary = incident_manager.get_incident_summary(incident_id)
        if not summary:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
        return jsonify({"status": "ok", "summary": summary}), 200

    @app.route("/api/incidents/<incident_id>/status", methods=["POST"])
    def update_incident_status(incident_id: str):
        """Update incident workflow status and optional analyst notes."""
        data = request.get_json(silent=True) or {}
        target_status = data.get("status")
        if not target_status:
            return jsonify({"status": "error", "message": "Missing 'status' field in request body"}), 400
        analyst_note = data.get("analyst_note")
        resolution = data.get("resolution")

        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status=target_status,
            analyst_note=analyst_note,
            resolution=resolution,
        )
        if not success:
            code = 404 if "not found" in msg.lower() else 400
            return jsonify({"status": "error", "message": msg}), code

        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/acknowledge", methods=["POST"])
    def acknowledge_incident(incident_id: str):
        """Operator shortcut to acknowledge an incident."""
        data = request.get_json(silent=True) or {}
        note = data.get("analyst_note", "Incident acknowledged by operator")
        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="ACKNOWLEDGED",
            analyst_note=note,
        )
        if not success:
            code = 404 if "not found" in msg.lower() else 400
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
    def resolve_incident(incident_id: str):
        """Operator shortcut to resolve an incident with resolution reason."""
        data = request.get_json(silent=True) or {}
        resolution = data.get("resolution", "Resolved by operator")
        note = data.get("analyst_note")
        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="RESOLVED",
            analyst_note=note,
            resolution=resolution,
        )
        if not success:
            code = 404 if "not found" in msg.lower() else 400
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/close", methods=["POST"])
    def close_incident(incident_id: str):
        """Operator shortcut to close an incident."""
        data = request.get_json(silent=True) or {}
        resolution = data.get("resolution", "Closed by operator")
        note = data.get("analyst_note")
        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="CLOSED",
            analyst_note=note,
            resolution=resolution,
        )
        if not success:
            code = 404 if "not found" in msg.lower() else 400
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/reopen", methods=["POST"])
    def reopen_incident(incident_id: str):
        """Operator shortcut to reopen a resolved or closed incident."""
        data = request.get_json(silent=True) or {}
        note = data.get("analyst_note", "Reopened by operator")
        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="OPEN",
            analyst_note=note,
        )
        if not success:
            code = 404 if "not found" in msg.lower() else 400
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

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
        if telemetry_worker:
            emit("host_telemetry", telemetry_worker.get_current_telemetry())
        if host_manager:
            emit("host_status", host_manager.get_status())
        if arp_detector:
            emit("network_status", {
                "arp": arp_detector.get_status(),
                "icmp_sweep": {
                    "enabled": True,
                    "window_sec": detector.icmp_sweep_window_sec if detector else 10.0,
                    "threshold": detector.icmp_sweep_threshold if detector else 10,
                    "tracked_sources": len(detector._icmp_sweep_state) if detector else 0,
                },
            })
        try:
            emit("security_summary", query_security_summary())
            emit("incident_stats", query_incident_stats())
        except Exception:
            pass

    @socketio.on("disconnect")
    def handle_disconnect():
        """Handle client Socket.IO disconnection."""
        pass

    @socketio.on("ping_server")
    def handle_ping(data):
        """Handle optional client ping test."""
        emit("pong_client", {"response": "pong", "received": data})

    # Start live capture, ML worker, telemetry worker, host manager, and metrics emitter if requested
    is_testing = app.config.get("TESTING", False)
    if start_capture and not is_testing:
        packet_capture.start()
        ml_detector.start()
        telemetry_worker.start()
        host_manager.start()

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
        if telemetry_worker:
            telemetry_worker.stop()
        if host_manager:
            host_manager.stop()

