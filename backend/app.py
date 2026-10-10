"""NetSentinel Flask Backend Application.

Main entry point for the NetSentinel REST API, real-time Socket.IO connection server,
packet capture lifecycle, rule-based intrusion detection, unsupervised ML anomaly detection,
composite risk scoring, automated iptables firewall mitigation, durable event persistence,
and host system telemetry sampling.
"""

import platform
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, g

from flask_cors import CORS
from flask_socketio import SocketIO, emit

from config import Config, resolve_network_interface
from config_validator import ConfigValidator, NETSENTINEL_VERSION, ConfigurationError
from logging_config import setup_logging
from security_middleware import SecurityMiddleware
from lifecycle import LifecycleManager, check_firewall_capabilities
from database import (
    init_db,
    check_database_health,
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
    save_fim_baseline_record,
    get_all_fim_baseline_records,
    query_fim_baseline,
    query_fim_stats,
    query_fim_events,
    save_ti_cache_record,
    get_all_ti_cache_records,
    save_ti_observation_record,
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
from threat_intel import ThreatIntelService, is_eligible_public_ip
from auth import (
    Permission,
    login_required,
    permission_required,
    bootstrap_admin_if_needed,
)
from auth.routes import auth_bp

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
threat_intel_service: ThreatIntelService = None
metrics_thread: threading.Thread = None
lifecycle_manager: LifecycleManager = None
app_start_time: float = time.time()


def create_app(config_class=Config, start_capture: bool = True) -> Tuple[Flask, SocketIO]:
    """Application factory for NetSentinel Flask Backend."""
    global packet_capture, detector, ml_detector, risk_engine, firewall, telemetry_worker, host_manager, arp_detector, incident_manager, threat_intel_service, metrics_thread, lifecycle_manager, app_start_time




    app = Flask(__name__)
    if isinstance(config_class, type):
        app.config.from_object(config_class)
    elif isinstance(config_class, dict):
        app.config.update(config_class)
    else:
        app.config.from_object(config_class)

    # 1. Initialize Structured Logging
    log_level = app.config.get("LOG_LEVEL", "INFO")
    setup_logging(log_level)

    # 2. Central Configuration Validation
    ConfigValidator.validate_or_raise(app.config)

    # 3. Setup Lifecycle Manager
    lifecycle_manager = LifecycleManager()
    app.lifecycle_manager = lifecycle_manager
    app.start_time = time.time()
    app_start_time = app.start_time

    # 4. CORS Hardening
    cors_origins = app.config.get("CORS_ORIGINS", ["http://localhost:5173", "http://127.0.0.1:5173", "http://10.0.2.3:5173"])
    if isinstance(cors_origins, str):
        cors_origins = [x.strip() for x in cors_origins.split(",") if x.strip()]
    elif isinstance(cors_origins, (list, tuple, set)):
        cors_origins = list(cors_origins)

    # Automatically ensure active interface IPv4 addresses on port 5173 are included if not already present
    try:
        import psutil
        for iface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if getattr(addr, "family", None) == socket.AF_INET:
                    ip = addr.address
                    if ip and not ip.startswith("127."):
                        dev_origin = f"http://{ip}:5173"
                        if dev_origin not in cors_origins:
                            cors_origins.append(dev_origin)
    except Exception:
        pass

    socket_cors = "*" if "*" in cors_origins else cors_origins
    CORS(app, resources={r"/api/*": {"origins": cors_origins}, r"/socket.io/*": {"origins": socket_cors}})

    # 5. Initialize Security Middleware (Request correlation, rate limiting, security headers, error normalization)
    security_mw = SecurityMiddleware(
        app=app,
        rate_limit=app.config.get("API_RATE_LIMIT", 240),
        sensitive_rate_limit=app.config.get("SENSITIVE_RATE_LIMIT", 10),
        enable_rate_limiting=not app.config.get("TESTING", False),
    )
    app.security_middleware = security_mw

    # 6. Initialize Database
    init_db(app)
    bootstrap_admin_if_needed(app)

    # 7. Register Auth Blueprint
    app.register_blueprint(auth_bp)

    # 8. Initialize Flask-SocketIO
    socketio = SocketIO(app, cors_allowed_origins=socket_cors, async_mode="threading")

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

    # 6. Initialize Host-Based Intrusion Detection Manager (Phase 7 & Phase 10)
    host_cfg = dict(app.config.get("HOST_DETECTION_SETTINGS", {}))
    if app.config.get("FIM_SETTINGS"):
        host_cfg.update(app.config.get("FIM_SETTINGS"))
    host_manager = HostDetectionManager(config=host_cfg)
    app.host_manager = host_manager

    if hasattr(host_manager, "file_integrity"):
        def _save_baseline_with_context(record_data, meta=None):
            with app.app_context():
                return save_fim_baseline_record(record_data, meta)

        def _load_baseline_with_context():
            with app.app_context():
                return get_all_fim_baseline_records()

        host_manager.file_integrity.set_persistence(
            loader=_load_baseline_with_context,
            saver=_save_baseline_with_context,
        )
        with app.app_context():
            host_manager.file_integrity.initialize()
    app.fim_monitor = getattr(host_manager, "file_integrity", None)



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

    # 9. Initialize Threat Intelligence Service (Phase 11)
    threat_intel_service = ThreatIntelService(config=app.config.get("TI_SETTINGS"))
    app.threat_intel_service = threat_intel_service

    def _save_ti_cache_with_context(**kwargs):
        with app.app_context():
            return save_ti_cache_record(**kwargs)

    def _load_ti_cache_with_context():
        with app.app_context():
            return get_all_ti_cache_records()

    threat_intel_service.cache.set_persistence(
        saver=_save_ti_cache_with_context,
        loader=_load_ti_cache_with_context,
    )
    with app.app_context():
        threat_intel_service.cache.load_persisted()

    def _on_threat_intel_updated(intel_data: Dict[str, Any]) -> None:
        try:
            socketio.emit("threat_intel_update", intel_data)
        except Exception:
            pass

        try:
            src_ip = intel_data.get("ip")
            if src_ip and incident_manager:
                with app.app_context():
                    inc = incident_manager.correlate_threat_intel(src_ip, intel_data)
                    inc_id = inc.incident_id if inc else None
                    save_ti_observation_record(
                        source_ip=src_ip,
                        provider="Aggregated",
                        reputation=intel_data.get("reputation", "UNKNOWN"),
                        confidence=float(intel_data.get("confidence", 0.0)),
                        summary=intel_data,
                        incident_id=inc_id,
                        expires_at=intel_data.get("expires_at"),
                    )
        except Exception as ex:
            app.logger.debug("Error correlating threat intel: %s", ex)

    threat_intel_service.on_intel_updated = _on_threat_intel_updated

    # Wire periodic worker activity callbacks to lifecycle heartbeats
    if hasattr(ml_detector, "set_heartbeat_callback"):
        ml_detector.set_heartbeat_callback(lambda: lifecycle_manager.record_heartbeat("ml_detector"))
    if hasattr(telemetry_worker, "set_heartbeat_callback"):
        telemetry_worker.set_heartbeat_callback(lambda: lifecycle_manager.record_heartbeat("telemetry"))
    if hasattr(host_manager, "set_heartbeat_callback"):
        host_manager.set_heartbeat_callback(lambda: lifecycle_manager.record_heartbeat("host_manager"))

    # Connect rule detector security events to persistence, Socket.IO, and Risk Engine
    def _on_security_event(event: SecurityEvent) -> None:
        try:
            lifecycle_manager.record_heartbeat("detector")
        except Exception:
            pass
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

        # Phase 11: Async queue for external Threat Intelligence enrichment (never blocks hot path)
        ti_summary = None
        if threat_intel_service and threat_intel_service.enabled:
            threat_intel_service.queue_ip(event.source_ip)
            ti_summary = threat_intel_service.get_cached_summary(event.source_ip)

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
                    ti_summary=ti_summary,
                )
                if lifecycle_manager:
                    lifecycle_manager.record_heartbeat("risk_engine")

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
                if lifecycle_manager:
                    lifecycle_manager.record_heartbeat("incident_manager")

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

                assessment = None
                if risk_engine:
                    src_ip = getattr(event, "source_ip", None)
                    dst_ip = getattr(event, "destination_ip", None)
                    assessment = risk_engine.assess(
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        rule_alerts=[],
                        ml_anomaly_score=event.anomaly_score,
                    )
                    if lifecycle_manager:
                        lifecycle_manager.record_heartbeat("risk_engine")
                    save_assessment_record(assessment)
                    try:
                        socketio.emit("risk_assessment", assessment.to_dict())
                        socketio.emit("risk_status", risk_engine.get_stats())
                    except Exception:
                        pass

                incident_manager.correlate_security_event(event, risk_assessment=assessment)
                if lifecycle_manager:
                    lifecycle_manager.record_heartbeat("incident_manager")
        except Exception as ex:
            app.logger.debug("Error in ML anomaly pipeline: %s", ex)


    ml_detector.add_anomaly_callback(_on_ml_anomaly)

    # Connect host detector security events to persistence, Socket.IO, and Risk Engine
    def _on_host_security_event(event: SecurityEvent) -> None:
        try:
            socketio.emit("host_security_event", event.to_dict())
            if (event.detection_type or "").upper() in (
                "FILE_CREATED", "FILE_DELETED", "FILE_MODIFIED", "FILE_REPLACED", "FILE_METADATA_CHANGED"
            ):
                if hasattr(host_manager, "file_integrity"):
                    socketio.emit("fim_status", host_manager.file_integrity.get_status())
        except Exception:
            pass
        _on_security_event(event)


    host_manager.add_event_callback(_on_host_security_event)
    arp_detector.add_event_callback(_on_security_event)

    # 6. Resolve network interface & initialize PacketCapture
    configured_iface = app.config.get("NETWORK_INTERFACE")
    active_iface = resolve_network_interface(configured_iface)
    packet_capture = PacketCapture(interface=active_iface, configured_interface=configured_iface)
    app.packet_capture = packet_capture

    # Connect rule detector, ML detector, and ARP detector as observers to the single raw packet stream
    def _on_capture_packet(pkt: Any) -> None:
        try:
            detector.analyze_packet(pkt)
            lifecycle_manager.record_heartbeat("detector")
        except Exception:
            pass

        try:
            ml_detector.process_packet(pkt)
        except Exception:
            pass

        try:
            arp_detector.process_packet(pkt)
            lifecycle_manager.record_heartbeat("arp_detector")
        except Exception:
            pass

    packet_capture.add_packet_callback(_on_capture_packet)

    # Define genuine domain health checks for each subsystem
    def _check_packet_capture_health() -> Tuple[bool, Optional[str]]:
        if not packet_capture:
            return False, "PacketCapture instance is null"
        st = packet_capture.runtime_status
        if st in ("stopped", "idle"):
            return True, None
        if st in ("permission_denied", "error"):
            return False, packet_capture.error_message or f"Capture error: {st}"
        if packet_capture._capture_thread and not packet_capture._capture_thread.is_alive():
            return False, "Packet capture thread is not alive"
        return True, None

    def _check_detector_health() -> Tuple[bool, Optional[str]]:
        if not detector:
            return False, "TrafficDetector instance is null"
        if not hasattr(detector, "_lock") or not hasattr(detector, "_port_scan_state"):
            return False, "TrafficDetector state corrupted"
        return True, None

    def _check_ml_detector_health() -> Tuple[bool, Optional[str]]:
        if not ml_detector:
            return False, "MLAnomalyDetector instance is null"
        if ml_detector._worker_thread and ml_detector._worker_thread.ident is not None:
            if not ml_detector._worker_thread.is_alive():
                return False, "ML anomaly detector background thread is dead"
        if not hasattr(ml_detector, "model") or ml_detector.model is None:
            return False, "ML model not initialized"
        return True, None

    def _check_risk_engine_health() -> Tuple[bool, Optional[str]]:
        if not risk_engine:
            return False, "RiskEngine instance is null"
        if not hasattr(risk_engine, "_lock") or not hasattr(risk_engine, "_ip_history"):
            return False, "RiskEngine state corrupted"
        return True, None

    def _check_firewall_health() -> Tuple[bool, Optional[str]]:
        if not firewall:
            return False, "FirewallManager instance is null"
        if not firewall.enabled:
            return True, None
        return True, None

    def _check_telemetry_health() -> Tuple[bool, Optional[str]]:
        if not telemetry_worker:
            return False, "TelemetryWorker instance is null"
        if telemetry_worker._thread and telemetry_worker._thread.ident is not None:
            if not telemetry_worker._thread.is_alive():
                return False, "TelemetryWorker background thread is dead"
        return True, None

    def _check_host_manager_health() -> Tuple[bool, Optional[str]]:
        if not host_manager:
            return False, "HostDetectionManager instance is null"
        if not host_manager.enabled:
            return True, None
        if host_manager._thread and host_manager._thread.ident is not None:
            if not host_manager._thread.is_alive():
                return False, "HostDetectionManager background thread is dead"
        return True, None

    def _check_arp_detector_health() -> Tuple[bool, Optional[str]]:
        if not arp_detector:
            return False, "ARPDetector instance is null"
        if not hasattr(arp_detector, "_lock") or not hasattr(arp_detector, "_ip_to_mac"):
            return False, "ARPDetector state corrupted"
        return True, None

    def _check_incident_manager_health() -> Tuple[bool, Optional[str]]:
        if not incident_manager:
            return False, "IncidentManager instance is null"
        if not hasattr(incident_manager, "_lock") or not hasattr(incident_manager, "_active_by_key"):
            return False, "IncidentManager state corrupted"
        return True, None

    def _check_threat_intel_health() -> Tuple[bool, Optional[str]]:
        if not threat_intel_service:
            return False, "ThreatIntelService instance is null"
        if not threat_intel_service.enabled:
            return True, None
        return True, None

    # Register all subsystem workers with LifecycleManager
    lifecycle_manager.register_worker(
        name="packet_capture",
        instance=packet_capture,
        role="Linux AF_PACKET Raw Frame Capture Engine",
        is_optional=False,
        health_check=_check_packet_capture_health,
    )
    lifecycle_manager.register_worker(
        name="detector",
        instance=detector,
        role="Rule-Based Intrusion Detector",
        is_optional=False,
        health_check=_check_detector_health,
    )
    lifecycle_manager.register_worker(
        name="ml_detector",
        instance=ml_detector,
        role="ML Anomaly Detector",
        is_optional=False,
        health_check=_check_ml_detector_health,
    )
    lifecycle_manager.register_worker(
        name="risk_engine",
        instance=risk_engine,
        role="Composite Risk Assessment Engine",
        is_optional=False,
        health_check=_check_risk_engine_health,
    )
    lifecycle_manager.register_worker(
        name="firewall",
        instance=firewall,
        role="Linux iptables Firewall Manager",
        is_optional=True,
        health_check=_check_firewall_health,
    )
    fw_cap = check_firewall_capabilities(firewall)
    firewall.capability_status = fw_cap

    lifecycle_manager.register_worker(
        name="telemetry",
        instance=telemetry_worker,
        role="Host System Telemetry Worker",
        is_optional=False,
        health_check=_check_telemetry_health,
    )
    lifecycle_manager.register_worker(
        name="host_manager",
        instance=host_manager,
        role="Host Intrusion Detection & FIM Manager",
        is_optional=False,
        health_check=_check_host_manager_health,
    )
    lifecycle_manager.register_worker(
        name="arp_detector",
        instance=arp_detector,
        role="ARP Spoofing & Cache Poisoning Detector",
        is_optional=False,
        health_check=_check_arp_detector_health,
    )
    lifecycle_manager.register_worker(
        name="incident_manager",
        instance=incident_manager,
        role="Security Incident Correlator",
        is_optional=False,
        health_check=_check_incident_manager_health,
    )
    lifecycle_manager.register_worker(
        name="threat_intel",
        instance=threat_intel_service,
        role="Threat Intelligence Enrichment Service",
        is_optional=True,
        health_check=_check_threat_intel_health,
    )

    # Register API Routes
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """Health check endpoint to verify backend operational status (liveness probe)."""
        return jsonify({
            "status": "ok",
            "alive": True,
            "service": "NetSentinel Backend",
            "version": Config.VERSION,
            "timestamp": time.time(),
            "request_id": getattr(g, "request_id", "-"),
        }), 200

    @app.route("/api/ready", methods=["GET"])
    def readiness_check():
        """Readiness check endpoint verifying database connectivity and core workers."""
        if lifecycle_manager:
            lifecycle_manager.check_all_workers_health()
        db_health = check_database_health()
        is_ready, worker_checks = lifecycle_manager.assess_readiness() if lifecycle_manager else (True, {})
        overall_ready = db_health.get("healthy", False) and is_ready

        status_code = 200 if overall_ready else 503
        return jsonify({
            "ready": overall_ready,
            "checks": {
                "database": "ok" if db_health.get("healthy") else "failed",
                "capture": worker_checks.get("packet_capture", "unknown"),
                "configuration": "ok",
                "workers": worker_checks,
            },
            "timestamp": time.time(),
            "request_id": getattr(g, "request_id", "-"),
        }), status_code

    @app.route("/api/system/status", methods=["GET"])
    @login_required
    def get_system_status():
        """Comprehensive runtime operational diagnostics and subsystem health."""
        if lifecycle_manager:
            lifecycle_manager.check_all_workers_health()
        now = time.time()
        uptime = round(now - app_start_time, 2)
        db_health = check_database_health()
        fw_cap_status = check_firewall_capabilities(firewall) if firewall else {"capable": False, "mode": "disabled"}

        capture_metrics = packet_capture.get_metrics() if packet_capture else {}
        capture_status = capture_metrics.get("status", "stopped")
        capture_err = capture_metrics.get("error", None)

        diagnostics = {
            "status": "ok",
            "application": {
                "name": "NetSentinel",
                "version": Config.VERSION,
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "uptime_seconds": uptime,
                "start_time": app_start_time,
            },
            "database": db_health,
            "firewall": {
                **fw_cap_status,
                "active_blocks": len(firewall._blocked_ips) if firewall else 0,
                "dry_run": firewall.dry_run if firewall else True,
                "auto_block": firewall.auto_block if firewall else False,
            },
            "packet_capture": {
                "status": capture_status,
                "interface": capture_metrics.get("interface", "none"),
                "configured_interface": capture_metrics.get("configured_interface", "none"),
                "actual_interface": capture_metrics.get("actual_interface", None),
                "socket_state": capture_metrics.get("socket_state", "CLOSED"),
                "error": capture_err,
                "total_packets": capture_metrics.get("total_packets", 0),
            },
            "workers": lifecycle_manager.get_all_worker_statuses() if lifecycle_manager else {},
            "configuration": Config.get_redacted_dict() if hasattr(Config, "get_redacted_dict") else {},
            "timestamp": now,
            "request_id": getattr(g, "request_id", "-"),
        }
        return jsonify(diagnostics), 200

    @app.route("/api/metrics", methods=["GET"])
    @login_required
    def get_metrics():
        """REST endpoint to retrieve current packet capture metrics snapshot."""
        return jsonify(packet_capture.get_metrics()), 200

    @app.route("/api/alerts", methods=["GET"])
    @login_required
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
    @login_required
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
    @login_required
    def get_ml_status():
        """REST endpoint to retrieve ML anomaly detection model status."""
        return jsonify(ml_detector.get_status()), 200

    @app.route("/api/ml/metrics", methods=["GET"])
    @login_required
    def get_ml_metrics():
        """REST endpoint to retrieve ML window history and recent anomalies."""
        return jsonify(ml_detector.get_metrics()), 200

    # Risk Engine & Firewall Endpoints
    @app.route("/api/risk/recent", methods=["GET"])
    @login_required
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
    @login_required
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
    @login_required
    def get_risk_stats():
        """REST endpoint to retrieve composite risk statistics."""
        return jsonify({
            "status": "ok",
            "stats": risk_engine.get_stats(),
        }), 200

    @app.route("/api/security/summary", methods=["GET"])
    @login_required
    def get_security_summary():
        """REST endpoint to retrieve aggregate security metrics across events, risks, and mitigations."""
        since = request.args.get("since", None, type=float)
        summary = query_security_summary(since_timestamp=since)
        return jsonify({"status": "ok", "summary": summary}), 200

    # Host Telemetry Endpoints (Phase 6)
    @app.route("/api/telemetry/current", methods=["GET"])
    @login_required
    def get_current_telemetry():
        """REST endpoint to retrieve instantaneous host telemetry snapshot."""
        data = telemetry_worker.get_current_telemetry() if telemetry_worker else {}
        return jsonify({"status": "ok", "telemetry": data}), 200

    @app.route("/api/telemetry/history", methods=["GET"])
    @login_required
    def get_telemetry_history():
        """REST endpoint to retrieve bounded historical host telemetry records."""
        limit = request.args.get("limit", 60, type=int)
        since = request.args.get("since", None, type=float)
        until = request.args.get("until", None, type=float)
        result = query_telemetry_history(limit=limit, since=since, until=until)
        return jsonify({"status": "ok", **result}), 200

    # Host-Based Intrusion Detection Endpoints (Phase 7)
    @app.route("/api/host/status", methods=["GET"])
    @login_required
    def get_host_status():
        """REST endpoint to retrieve host detection status (SSH detector & Process monitor)."""
        status = host_manager.get_status() if host_manager else {}
        return jsonify({"status": "ok", "host": status, "data": status}), 200

    @app.route("/api/host/events", methods=["GET"])
    @login_required
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
    @login_required
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
            "capture": metrics,
            "arp": arp_status,
            "icmp_sweep": icmp_status,
        }), 200

    @app.route("/api/network/arp", methods=["GET"])
    @login_required
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
    @login_required
    def get_firewall_status():
        """REST endpoint to retrieve firewall integration and safety status."""
        return jsonify({
            "status": "ok",
            "firewall": firewall.get_status(),
        }), 200

    @app.route("/api/firewall/blocked", methods=["GET"])
    @login_required
    def get_blocked_ips():
        """REST endpoint to retrieve list of currently blocked IPs."""
        blocked = firewall.list_blocked_ips()
        return jsonify({
            "status": "ok",
            "count": len(blocked),
            "blocked_ips": blocked,
        }), 200

    @app.route("/api/firewall/block", methods=["POST"])
    @permission_required(Permission.MANAGE_FIREWALL)
    def manual_block_ip():
        """REST endpoint to manually block a specific IP address on the managed chain."""
        data = request.get_json(silent=True) or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' field"}), 400

        ip_str = str(ip).strip()
        if len(ip_str) > 64:
            return jsonify({"status": "error", "message": "IP address exceeds maximum length of 64 characters"}), 400

        reason = str(data.get("reason", "Operator Manual Block")).strip()
        if len(reason) > 255:
            return jsonify({"status": "error", "message": "Reason exceeds maximum length of 255 characters"}), 400

        duration = data.get("duration", None)
        if duration is not None:
            try:
                duration = float(duration)
                if duration <= 0 or duration > 2592000:
                    return jsonify({"status": "error", "message": "Duration must be between 1 and 2592000 seconds"}), 400
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid 'duration' parameter"}), 400

        result = firewall.block_ip(ip_address=ip_str, reason=reason, duration=duration)
        if result.get("success"):
            try:
                with app.app_context():
                    save_firewall_action_record(
                        action="block",
                        source_ip=ip_str,
                        success=True,
                        reason=reason,
                        expires_at=result.get("expires_at"),
                    )
            except Exception as ex:
                app.logger.debug("Failed to persist manual block action: %s", ex)

            socketio.emit("firewall_action", {
                "timestamp": time.time(),
                "action": "block",
                "source_ip": ip_str,
                "success": True,
                "expires_at": result.get("expires_at"),
                "reason": reason,
            })

            incident_manager.correlate_firewall_action(
                action="block",
                source_ip=ip_str,
                reason=f"Operator Manual Block: {reason}",
                duration=duration,
                timestamp=time.time(),
            )
            return jsonify({"status": "ok", "result": result}), 200
        else:
            return jsonify({"status": "error", "result": result}), 400

    @app.route("/api/firewall/unblock", methods=["POST"])
    @permission_required(Permission.MANAGE_FIREWALL)
    def manual_unblock_ip():
        """REST endpoint to manually unblock an IP address from the managed chain."""
        data = request.get_json(silent=True) or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"status": "error", "message": "Missing 'ip' field"}), 400

        ip_str = str(ip).strip()
        if len(ip_str) > 64:
            return jsonify({"status": "error", "message": "IP address exceeds maximum length of 64 characters"}), 400

        result = firewall.unblock_ip(ip_address=ip_str)
        if result.get("success"):
            try:
                with app.app_context():
                    save_firewall_action_record(
                        action="unblock",
                        source_ip=ip_str,
                        success=True,
                        reason="Operator Manual Unblock",
                    )
            except Exception as ex:
                app.logger.debug("Failed to persist manual unblock action: %s", ex)

            socketio.emit("firewall_action", {
                "timestamp": time.time(),
                "action": "unblock",
                "source_ip": ip_str,
                "success": True,
                "expires_at": None,
                "reason": "Operator Manual Unblock",
            })

            incident_manager.correlate_firewall_action(
                action="unblock",
                source_ip=ip_str,
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
    @login_required
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
    @login_required
    def get_incident_stats():
        """Retrieve aggregated incident metrics (open/resolved counts, severity breakdown, top sources)."""
        since = request.args.get("since", None, type=float)
        stats = query_incident_stats(since_timestamp=since)
        return jsonify({"status": "ok", "stats": stats}), 200

    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    @login_required
    def get_incident_detail(incident_id: str):
        """Retrieve comprehensive incident record including correlated evidence items."""
        inc = incident_manager.get_incident(incident_id, include_evidence=True)
        if not inc:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404

        # Attach Threat Intelligence enrichment summary if available for primary_source_ip
        src_ip = inc.get("primary_source_ip")
        if src_ip and threat_intel_service:
            ti_summary = threat_intel_service.get_cached_summary(src_ip)
            if ti_summary:
                inc["threat_intelligence"] = ti_summary.to_dict()

        return jsonify({"status": "ok", "incident": inc}), 200


    @app.route("/api/incidents/<incident_id>/timeline", methods=["GET"])
    @login_required
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
    @login_required
    def get_incident_summary_report(incident_id: str):
        """Retrieve SOC-ready report summary for an incident."""
        summary = incident_manager.get_incident_summary(incident_id)
        if not summary:
            return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404
        return jsonify({"status": "ok", "summary": summary}), 200

    @app.route("/api/incidents/<incident_id>/status", methods=["POST"])
    @permission_required(Permission.MANAGE_INCIDENTS)
    def update_incident_status(incident_id: str):
        """Update incident workflow status and optional analyst notes."""
        data = request.get_json(silent=True) or {}
        target_status = data.get("status")
        if not target_status or not isinstance(target_status, str):
            return jsonify({"status": "error", "message": "Missing or invalid 'status' field in request body"}), 400
        
        target_status_str = str(target_status).strip().upper()
        analyst_note = data.get("analyst_note")
        resolution = data.get("resolution")

        if analyst_note is not None and len(str(analyst_note)) > 1000:
            return jsonify({"status": "error", "message": "Analyst note exceeds maximum length of 1000 characters"}), 400
        if resolution is not None and len(str(resolution)) > 1000:
            return jsonify({"status": "error", "message": "Resolution exceeds maximum length of 1000 characters"}), 400

        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status=target_status_str,
            analyst_note=analyst_note,
            resolution=resolution,
        )
        if not success:
            msg_lower = msg.lower()
            if "not found" in msg_lower:
                code = 404
            elif "cannot transition" in msg_lower or "invalid transition" in msg_lower:
                code = 409
            else:
                code = 400
            return jsonify({"status": "error", "message": msg}), code

        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/acknowledge", methods=["POST"])
    @permission_required(Permission.MANAGE_INCIDENTS)
    def acknowledge_incident(incident_id: str):
        """Operator shortcut to acknowledge an incident."""
        data = request.get_json(silent=True) or {}
        note = data.get("analyst_note", "Incident acknowledged by operator")
        if note is not None and len(str(note)) > 1000:
            return jsonify({"status": "error", "message": "Analyst note exceeds maximum length of 1000 characters"}), 400

        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="ACKNOWLEDGED",
            analyst_note=note,
        )
        if not success:
            msg_lower = msg.lower()
            code = 404 if "not found" in msg_lower else (409 if "cannot transition" in msg_lower else 400)
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
    @permission_required(Permission.MANAGE_INCIDENTS)
    def resolve_incident(incident_id: str):
        """Operator shortcut to resolve an incident with resolution reason."""
        data = request.get_json(silent=True) or {}
        resolution = data.get("resolution", "Resolved by operator")
        note = data.get("analyst_note")
        if note is not None and len(str(note)) > 1000:
            return jsonify({"status": "error", "message": "Analyst note exceeds maximum length of 1000 characters"}), 400
        if resolution is not None and len(str(resolution)) > 1000:
            return jsonify({"status": "error", "message": "Resolution exceeds maximum length of 1000 characters"}), 400

        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="RESOLVED",
            analyst_note=note,
            resolution=resolution,
        )
        if not success:
            msg_lower = msg.lower()
            code = 404 if "not found" in msg_lower else (409 if "cannot transition" in msg_lower else 400)
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/close", methods=["POST"])
    @permission_required(Permission.MANAGE_INCIDENTS)
    def close_incident(incident_id: str):
        """Operator shortcut to close an incident."""
        data = request.get_json(silent=True) or {}
        resolution = data.get("resolution", "Closed by operator")
        note = data.get("analyst_note")
        if note is not None and len(str(note)) > 1000:
            return jsonify({"status": "error", "message": "Analyst note exceeds maximum length of 1000 characters"}), 400
        if resolution is not None and len(str(resolution)) > 1000:
            return jsonify({"status": "error", "message": "Resolution exceeds maximum length of 1000 characters"}), 400

        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="CLOSED",
            analyst_note=note,
            resolution=resolution,
        )
        if not success:
            msg_lower = msg.lower()
            code = 404 if "not found" in msg_lower else (409 if "cannot transition" in msg_lower else 400)
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    @app.route("/api/incidents/<incident_id>/reopen", methods=["POST"])
    @permission_required(Permission.MANAGE_INCIDENTS)
    def reopen_incident(incident_id: str):
        """Operator shortcut to reopen a resolved or closed incident."""
        data = request.get_json(silent=True) or {}
        note = data.get("analyst_note", "Reopened by operator")
        if note is not None and len(str(note)) > 1000:
            return jsonify({"status": "error", "message": "Analyst note exceeds maximum length of 1000 characters"}), 400

        success, msg, inc_data = incident_manager.transition_status(
            incident_id=incident_id,
            target_status="OPEN",
            analyst_note=note,
        )
        if not success:
            msg_lower = msg.lower()
            code = 404 if "not found" in msg_lower else (409 if "cannot transition" in msg_lower else 400)
            return jsonify({"status": "error", "message": msg}), code
        return jsonify({"status": "ok", "message": msg, "incident": inc_data}), 200

    # --------------------------------------------------------------------------
    # File Integrity Monitoring (FIM) Endpoints (Phase 10)
    # --------------------------------------------------------------------------
    @app.route("/api/fim/status", methods=["GET"])
    @login_required
    def get_fim_status():
        """Retrieve operational state, scan metrics, and baseline statistics of FIM."""
        if not host_manager or not hasattr(host_manager, "file_integrity"):
            return jsonify({"enabled": False, "error": "FIM not initialized"}), 503
        return jsonify(host_manager.file_integrity.get_status()), 200

    @app.route("/api/fim/events", methods=["GET"])
    @login_required
    def get_fim_events():
        """Retrieve paginated historical file integrity security events."""
        limit = min(200, max(1, request.args.get("limit", 50, type=int)))
        offset = max(0, request.args.get("offset", 0, type=int))
        since = request.args.get("since", type=float)
        until = request.args.get("until", type=float)
        change_type = request.args.get("change_type", type=str)
        path = request.args.get("path", type=str)

        res = query_fim_events(
            limit=limit,
            offset=offset,
            since=since,
            until=until,
            change_type=change_type,
            path=path,
        )
        return jsonify(res), 200

    @app.route("/api/fim/baseline", methods=["GET"])
    @login_required
    def get_fim_baseline():
        """Retrieve paginated FIM baseline file records."""
        limit = min(500, max(1, request.args.get("limit", 100, type=int)))
        offset = max(0, request.args.get("offset", 0, type=int))
        status = request.args.get("status", type=str)
        path = request.args.get("path", type=str)

        res = query_fim_baseline(
            limit=limit,
            offset=offset,
            status=status,
            path=path,
        )
        return jsonify(res), 200

    @app.route("/api/fim/rebaseline", methods=["POST"])
    @permission_required(Permission.MANAGE_FIM)
    def post_fim_rebaseline():
        """Operator-controlled rebaseline of specified or all monitored paths."""
        if not host_manager or not hasattr(host_manager, "file_integrity"):
            return jsonify({"success": False, "error": "FIM not initialized"}), 503

        data = request.get_json(silent=True) or {}
        paths = data.get("paths")
        if paths is not None:
            if not isinstance(paths, list):
                return jsonify({"success": False, "error": "paths must be a list of file paths"}), 400
            for p in paths:
                if not isinstance(p, str) or len(p) > 512:
                    return jsonify({"success": False, "error": "Each path in paths must be a string <= 512 characters"}), 400

        with app.app_context():
            res = host_manager.file_integrity.rebuild_baseline(paths=paths)

        status = host_manager.file_integrity.get_status()
        socketio.emit("fim_status", status)
        return jsonify({
            "success": True,
            "message": "FIM baseline re-established",
            "summary": res,
            "status": status,
        }), 200

    # Threat Intelligence Endpoints (Phase 11)
    @app.route("/api/threat-intel/status", methods=["GET"])
    @login_required
    def get_threat_intel_status():
        """Retrieve operational status, configured providers, and metrics for Threat Intelligence."""
        if not threat_intel_service:
            return jsonify({
                "status": "ok",
                "threat_intel": {
                    "enabled": False,
                    "configured_providers": [],
                    "available_providers": [],
                    "queue_size": 0,
                    "cache_entries": 0,
                },
            }), 200
        return jsonify({
            "status": "ok",
            "threat_intel": threat_intel_service.get_status(),
        }), 200

    @app.route("/api/threat-intel/ip/<ip>", methods=["GET"])
    @login_required
    def get_threat_intel_ip(ip: str):
        """Query normalized threat intelligence information for an external IP indicator."""
        clean_ip = str(ip).strip()
        if not is_eligible_public_ip(clean_ip):
            return jsonify({
                "status": "ok",
                "ip": clean_ip,
                "eligible": False,
                "available": False,
                "reputation": "UNKNOWN",
                "reason": "ineligible_private_or_local",
                "message": "Only public, globally routable IPs are eligible for threat intelligence lookup.",
            }), 200

        if not threat_intel_service:
            return jsonify({
                "status": "ok",
                "ip": clean_ip,
                "eligible": True,
                "available": False,
                "reputation": "UNKNOWN",
                "message": "Threat Intelligence service not initialized",
            }), 200

        ti_summary = threat_intel_service.get_cached_summary(clean_ip, allow_stale=True)
        if not ti_summary:
            return jsonify({
                "status": "ok",
                "ip": clean_ip,
                "eligible": True,
                "available": False,
                "reputation": "UNKNOWN",
                "message": "Indicator is not currently cached.",
            }), 200

        return jsonify({
            "status": "ok",
            "ip": clean_ip,
            "eligible": True,
            "available": True,
            "intelligence": ti_summary.to_dict(),
        }), 200

    @app.route("/api/threat-intel/ip/<ip>/lookup", methods=["POST"])
    @permission_required(Permission.QUERY_THREAT_INTEL)
    def request_threat_intel_lookup(ip: str):
        """Explicitly request background threat intelligence enrichment for an eligible public IP."""
        clean_ip = str(ip).strip()
        if not is_eligible_public_ip(clean_ip):
            return jsonify({
                "status": "error",
                "message": "Ineligible IP indicator. Only public, globally routable IPs can be queried.",
            }), 400

        if not threat_intel_service or not threat_intel_service.enabled:
            return jsonify({
                "status": "error",
                "message": "Threat Intelligence service is disabled.",
            }), 400

        if not threat_intel_service.get_configured_providers():
            return jsonify({
                "status": "error",
                "message": "No threat intelligence providers configured with credentials.",
            }), 400

        queued = threat_intel_service.queue_ip(clean_ip, priority=True)
        if not queued:
            return jsonify({
                "status": "error",
                "message": "Enrichment queue is full or request could not be queued.",
            }), 429

        return jsonify({
            "status": "ok",
            "ip": clean_ip,
            "message": "Threat intelligence lookup queued for background enrichment.",
        }), 202

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
            if hasattr(host_manager, "file_integrity"):
                emit("fim_status", host_manager.file_integrity.get_status())
        if threat_intel_service:
            emit("threat_intel_status", threat_intel_service.get_status())
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
            while not lifecycle_manager.shutdown_event.is_set():
                time.sleep(interval)
                if lifecycle_manager.shutdown_event.is_set():
                    break
                try:
                    if lifecycle_manager:
                        lifecycle_manager.check_all_workers_health()
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
        if hasattr(app, "lifecycle_manager") and app.lifecycle_manager:
            app.lifecycle_manager.stop_all(timeout=5.0)
        else:
            if packet_capture:
                packet_capture.stop()
            if ml_detector:
                ml_detector.stop()
            if telemetry_worker:
                telemetry_worker.stop()
            if host_manager:
                host_manager.stop()
            if threat_intel_service:
                threat_intel_service.stop()


