import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './pages/Dashboard';
import {
  checkBackendHealth,
  fetchTrafficMetrics,
  fetchSecurityAlerts,
  fetchMLStatus,
  fetchMLMetrics,
  fetchRecentRisks,
  fetchRiskStats,
  fetchFirewallStatus,
  fetchBlockedIPs,
  manualUnblockIP,
  fetchSecurityEvents,
  fetchSecuritySummary,
  fetchTelemetryCurrent,
  fetchTelemetryHistory,
  fetchHostStatus,
  fetchHostEvents,
  fetchNetworkStatus,
  fetchARPMappings,
  fetchIncidents,
  fetchIncidentStats,
  acknowledgeIncident,
  resolveIncident,
  closeIncident,
  reopenIncident,
  fetchFimStatus,
  fetchFimEvents,
  triggerFimRebaseline,
  fetchThreatIntelStatus,
  fetchThreatIntelIP,
  requestThreatIntelLookup,
} from './services/api';
import { socket, initSocketConnection } from './services/socket';
import './App.css';

export function App() {
  const [apiStatus, setApiStatus] = useState({ connected: false, data: null });
  const [socketConnected, setSocketConnected] = useState(socket.connected);
  const [trafficMetrics, setTrafficMetrics] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [mlStatus, setMlStatus] = useState(null);
  const [mlMetrics, setMlMetrics] = useState({ window_history: [], recent_anomalies: [] });
  const [riskAssessments, setRiskAssessments] = useState([]);
  const [riskStats, setRiskStats] = useState(null);
  const [firewallStatus, setFirewallStatus] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState([]);

  // Phase 6: Host Telemetry & Historical Persistence States
  const [hostTelemetry, setHostTelemetry] = useState(null);
  const [telemetryHistory, setTelemetryHistory] = useState([]);
  const [securitySummary, setSecuritySummary] = useState(null);
  const [historicalEvents, setHistoricalEvents] = useState([]);

  // Phase 7: Host-Based Intrusion Detection (HIDS) State
  const [hostStatus, setHostStatus] = useState(null);

  // Phase 8: Advanced Network Threat Detection (ARP & ICMP Sweep) State
  const [networkStatus, setNetworkStatus] = useState(null);
  const [arpMappings, setArpMappings] = useState([]);

  // Phase 9: Incident Correlation & Investigation State
  const [incidents, setIncidents] = useState([]);
  const [incidentStats, setIncidentStats] = useState(null);

  // Phase 10: File Integrity Monitoring (FIM) State
  const [fimStatus, setFimStatus] = useState(null);
  const [fimEvents, setFimEvents] = useState([]);

  // Phase 11: Threat Intelligence (TI) State
  const [threatIntelStatus, setThreatIntelStatus] = useState(null);



  const refreshFirewall = async () => {
    const fw = await fetchFirewallStatus();
    if (fw) setFirewallStatus(fw);
    const blk = await fetchBlockedIPs();
    if (blk) setBlockedIPs(blk);
  };

  const handleUnblock = async (ip) => {
    await manualUnblockIP(ip);
    await refreshFirewall();
  };

  const refreshHistory = async (params = {}) => {
    const res = await fetchSecurityEvents(params);
    if (res && res.events) {
      setHistoricalEvents(res.events);
    }
  };

  const refreshIncidents = async (params = {}) => {
    const res = await fetchIncidents(params);
    if (res && res.incidents) {
      setIncidents(res.incidents);
    }
    const statsRes = await fetchIncidentStats();
    if (statsRes) {
      setIncidentStats(statsRes);
    }
  };

  const handleAcknowledge = async (incidentId, note = '') => {
    const res = await acknowledgeIncident(incidentId, note);
    if (res.status === 'ok') {
      await refreshIncidents();
    }
    return res;
  };

  const handleResolve = async (incidentId, resolution = '', note = '') => {
    const res = await resolveIncident(incidentId, resolution, note);
    if (res.status === 'ok') {
      await refreshIncidents();
    }
    return res;
  };

  const handleClose = async (incidentId, resolution = '', note = '') => {
    const res = await closeIncident(incidentId, resolution, note);
    if (res.status === 'ok') {
      await refreshIncidents();
    }
    return res;
  };

  const handleReopen = async (incidentId, note = '') => {
    const res = await reopenIncident(incidentId, note);
    if (res.status === 'ok') {
      await refreshIncidents();
    }
    return res;
  };

  const refreshFim = async (params = {}) => {
    const status = await fetchFimStatus();
    if (status) setFimStatus(status);
    const evts = await fetchFimEvents(params);
    if (evts && evts.events) setFimEvents(evts.events);
  };

  const handleFimRebaseline = async (paths = null) => {
    const res = await triggerFimRebaseline(paths);
    if (res && res.success) {
      await refreshFim();
    }
    return res;
  };


  useEffect(() => {
    // Check initial API health and fetch component datasets
    const fetchHealthAndData = async () => {
      const res = await checkBackendHealth();
      setApiStatus(res);
      if (res.connected) {
        if (!trafficMetrics) {
          const initialMetrics = await fetchTrafficMetrics();
          if (initialMetrics) setTrafficMetrics(initialMetrics);
        }
        const initialAlerts = await fetchSecurityAlerts(50);
        if (initialAlerts && initialAlerts.length > 0) setAlerts(initialAlerts);

        const initialMLStatus = await fetchMLStatus();
        if (initialMLStatus) setMlStatus(initialMLStatus);

        const initialMLMetrics = await fetchMLMetrics();
        if (initialMLMetrics) setMlMetrics(initialMLMetrics);

        const initialRisks = await fetchRecentRisks(20);
        if (initialRisks && initialRisks.length > 0) setRiskAssessments(initialRisks);

        const initialRiskStats = await fetchRiskStats();
        if (initialRiskStats) setRiskStats(initialRiskStats);

        const initialFW = await fetchFirewallStatus();
        if (initialFW) setFirewallStatus(initialFW);

        const initialBlocked = await fetchBlockedIPs();
        if (initialBlocked) setBlockedIPs(initialBlocked);

        // Phase 6 Initial Fetches
        const curTelem = await fetchTelemetryCurrent();
        if (curTelem) setHostTelemetry(curTelem);

        const histTelem = await fetchTelemetryHistory(30);
        if (histTelem && histTelem.length > 0) {
          setTelemetryHistory(
            histTelem.map((t) => ({
              time: new Date(t.timestamp * 1000).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              }),
              cpu: t.cpu_percent,
              ram: t.memory_percent,
              tx_bps: t.host_tx_bps,
              rx_bps: t.host_rx_bps,
              tx_pps: t.host_tx_pps,
              rx_pps: t.host_rx_pps,
            }))
          );
        }

        const summary = await fetchSecuritySummary();
        if (summary) setSecuritySummary(summary);

        const eventsRes = await fetchSecurityEvents({ limit: 50 });
        if (eventsRes && eventsRes.events) setHistoricalEvents(eventsRes.events);

        const hStatus = await fetchHostStatus();
        if (hStatus) setHostStatus(hStatus);

        const nStatus = await fetchNetworkStatus();
        if (nStatus) setNetworkStatus(nStatus);

        const arpRes = await fetchARPMappings(20);
        if (arpRes && arpRes.mappings) setArpMappings(arpRes.mappings);

        const incRes = await fetchIncidents({ limit: 50 });
        if (incRes && incRes.incidents) setIncidents(incRes.incidents);

        const incStatsRes = await fetchIncidentStats();
        if (incStatsRes) setIncidentStats(incStatsRes);

        const fStatus = await fetchFimStatus();
        if (fStatus) setFimStatus(fStatus);

        const fEvents = await fetchFimEvents({ limit: 20 });
        if (fEvents && fEvents.events) setFimEvents(fEvents.events);

        const tiStatus = await fetchThreatIntelStatus();
        if (tiStatus) setThreatIntelStatus(tiStatus);
      }
    };



    fetchHealthAndData();
    const interval = setInterval(fetchHealthAndData, 5000);

    // Initialize Socket.IO connection handlers
    const cleanupSocket = initSocketConnection(
      (connected) => {
        setSocketConnected(connected);
      },
      (metrics) => {
        setTrafficMetrics(metrics);
        const nowStr = new Date(metrics.timestamp * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });

        setTrafficHistory((prev) => {
          const updated = [
            ...prev,
            {
              time: nowStr,
              pps: metrics.packets_per_sec,
              bps: metrics.bytes_per_sec,
            },
          ];
          return updated.slice(-20);
        });
      },
      (newAlert) => {
        setAlerts((prev) => {
          if (prev.some((a) => a.event_id === newAlert.event_id)) return prev;
          return [newAlert, ...prev].slice(0, 100);
        });
        setHistoricalEvents((prev) => {
          if (prev.some((e) => e.event_id === newAlert.event_id)) return prev;
          return [newAlert, ...prev].slice(0, 100);
        });
      },
      (newMLAnomaly) => {
        setMlMetrics((prev) => {
          const existing = prev.recent_anomalies || [];
          if (existing.some((a) => a.event_id === newMLAnomaly.event_id)) return prev;
          return {
            ...prev,
            recent_anomalies: [newMLAnomaly, ...existing].slice(0, 50),
          };
        });

        setMlStatus((prev) =>
          prev
            ? {
                ...prev,
                total_anomalies_detected: (prev.total_anomalies_detected || 0) + 1,
                latest_prediction: 'ANOMALY',
                latest_anomaly_score: newMLAnomaly.anomaly_score,
                latest_raw_score: newMLAnomaly.raw_score,
              }
            : prev
        );
      },
      (statusUpdate) => {
        setMlStatus(statusUpdate);
      },
      (newRisk) => {
        setRiskAssessments((prev) => {
          if (prev.some((r) => r.assessment_id === newRisk.assessment_id)) return prev;
          return [newRisk, ...prev].slice(0, 50);
        });
        setRiskStats((prev) =>
          prev
            ? {
                ...prev,
                total_assessments: (prev.total_assessments || 0) + 1,
                highest_risk_score: Math.max(prev.highest_risk_score || 0, newRisk.combined_score),
              }
            : null
        );
      },
      (action) => {
        refreshFirewall();
      },
      (fwStatus) => {
        setFirewallStatus(fwStatus);
      },
      (blocked) => {
        setBlockedIPs(blocked);
      },
      (telem) => {
        setHostTelemetry(telem);
        const nowStr = new Date(telem.timestamp * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
        setTelemetryHistory((prev) => {
          const updated = [
            ...prev,
            {
              time: nowStr,
              cpu: telem.cpu_percent,
              ram: telem.memory_percent,
              tx_bps: telem.host_tx_bps,
              rx_bps: telem.host_rx_bps,
              tx_pps: telem.host_tx_pps,
              rx_pps: telem.host_rx_pps,
            },
          ];
          return updated.slice(-30);
        });
      },
      (summary) => {
        setSecuritySummary(summary);
      },
      (hostEvt) => {
        setAlerts((prev) => {
          if (prev.some((a) => a.event_id === hostEvt.event_id)) return prev;
          return [hostEvt, ...prev].slice(0, 100);
        });
        setHistoricalEvents((prev) => {
          if (prev.some((e) => e.event_id === hostEvt.event_id)) return prev;
          return [hostEvt, ...prev].slice(0, 100);
        });
        fetchHostStatus().then((st) => st && setHostStatus(st));
      },
      (hStatus) => {
        setHostStatus(hStatus);
      },
      (netStatus) => {
        setNetworkStatus(netStatus);
      },
      (newIncident) => {
        setIncidents((prev) => {
          const idx = prev.findIndex((i) => i.incident_id === newIncident.incident_id);
          if (idx >= 0) {
            const updated = [...prev];
            updated[idx] = newIncident;
            return updated;
          }
          return [newIncident, ...prev].slice(0, 100);
        });
        fetchIncidentStats().then((st) => st && setIncidentStats(st));
      },
      (updatedIncident) => {
        setIncidents((prev) => {
          const idx = prev.findIndex((i) => i.incident_id === updatedIncident.incident_id);
          if (idx >= 0) {
            const updated = [...prev];
            updated[idx] = updatedIncident;
            return updated;
          }
          return [updatedIncident, ...prev].slice(0, 100);
        });
      },
      (statusChange) => {
        setIncidents((prev) =>
          prev.map((inc) =>
            inc.incident_id === statusChange.incident_id
              ? {
                  ...inc,
                  status: statusChange.new_status,
                  analyst_note: statusChange.analyst_note || inc.analyst_note,
                  resolution: statusChange.resolution || inc.resolution,
                }
              : inc
          )
        );
        fetchIncidentStats().then((st) => st && setIncidentStats(st));
      },
      (stats) => {
        setIncidentStats(stats);
      },
      (fimStat) => {
        setFimStatus(fimStat);
      },
      (tiStat) => {
        setThreatIntelStatus(tiStat);
      },
      (tiUpdate) => {
        fetchThreatIntelStatus().then((st) => st && setThreatIntelStatus(st));
      }
    );

    return () => {
      clearInterval(interval);
      cleanupSocket();
    };
  }, []);

  return (
    <div className="app-container">
      <Header apiConnected={apiStatus.connected} socketConnected={socketConnected} />
      <main className="main-content">
        <Dashboard
          apiStatus={apiStatus}
          socketConnected={socketConnected}
          trafficMetrics={trafficMetrics}
          trafficHistory={trafficHistory}
          alerts={alerts}
          mlStatus={mlStatus}
          mlMetrics={mlMetrics}
          riskAssessments={riskAssessments}
          riskStats={riskStats}
          firewallStatus={firewallStatus}
          blockedIPs={blockedIPs}
          onUnblock={handleUnblock}
          hostTelemetry={hostTelemetry}
          telemetryHistory={telemetryHistory}
          securitySummary={securitySummary}
          historicalEvents={historicalEvents}
          onRefreshHistory={refreshHistory}
          hostStatus={hostStatus}
          networkStatus={networkStatus}
          arpMappings={arpMappings}
          incidents={incidents}
          incidentStats={incidentStats}
          onRefreshIncidents={refreshIncidents}
          onAcknowledgeIncident={handleAcknowledge}
          onResolveIncident={handleResolve}
          onCloseIncident={handleClose}
          onReopenIncident={handleReopen}
          fimStatus={fimStatus}
          fimEvents={fimEvents}
          onRefreshFim={refreshFim}
          onFimRebaseline={handleFimRebaseline}
          threatIntelStatus={threatIntelStatus}
          onRequestTILookup={requestThreatIntelLookup}
          onFetchTIIP={fetchThreatIntelIP}
        />
      </main>
    </div>
  );
}



export default App;
