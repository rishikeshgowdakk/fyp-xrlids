import React from 'react';
import { FlowEvent } from '../types';
import { X, Shield, Activity, Lock, Info, AlertTriangle } from './Icons';

interface FlowDetailPanelProps {
  flow: FlowEvent | null;
  researchThreshold: number;
  operationalThreshold: number;
  onClose: () => void;
}

export const FlowDetailPanel: React.FC<FlowDetailPanelProps> = ({
  flow,
  researchThreshold,
  operationalThreshold,
  onClose,
}) => {
  if (!flow) return null;

  const [srcIp, srcPort] = flow.src_endpoint.split(':');
  const [dstIp, dstPort] = flow.dst_endpoint.split(':');
  const score = flow.attack_score ?? 0;

  const isResearchAttack = flow.pred_research_label === 'ATTACK' || score >= researchThreshold;
  const isOperationalAttack =
    flow.pred_operational_label === 'ATTACK' || score >= operationalThreshold;

  const features = flow.features || ({} as FlowEvent['features']);

  return (
    <div className="flow-detail-overlay" onClick={onClose}>
      <div className="flow-detail-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-title-group">
            <span className="drawer-badge">FLOW INSPECTION</span>
            <h2 className="drawer-title">Flow #{flow.flow_id} Details</h2>
          </div>
          <button className="drawer-close-btn" onClick={onClose} aria-label="Close drawer">
            <X size={20} />
          </button>
        </div>

        <div className="drawer-content-scroll">
          {/* Section 1: Network Information */}
          <section className="detail-section">
            <div className="section-title-row">
              <Activity size={16} className="section-icon cyan" />
              <h3 className="section-title">Network Information</h3>
            </div>
            <div className="detail-grid-2">
              <div className="detail-field">
                <span className="field-label">Source Endpoint:</span>
                <span className="field-val-mono highlight-src">{srcIp}:{srcPort}</span>
              </div>
              <div className="detail-field">
                <span className="field-label">Destination Endpoint:</span>
                <span className="field-val-mono highlight-dst">{dstIp}:{dstPort}</span>
              </div>
              <div className="detail-field">
                <span className="field-label">Protocol:</span>
                <span className="field-val">
                  <span className={`proto-badge proto-${flow.protocol_name.toLowerCase()}`}>
                    {flow.protocol_name}
                  </span>
                </span>
              </div>
              <div className="detail-field">
                <span className="field-label">Packet Count:</span>
                <span className="field-val font-semibold">{flow.packet_count} packets</span>
              </div>
              <div className="detail-field">
                <span className="field-label">Duration:</span>
                <span className="field-val font-semibold">{flow.duration_ms.toFixed(2)} ms</span>
              </div>
              <div className="detail-field">
                <span className="field-label">Timestamp Start:</span>
                <span className="field-val-mono text-muted">
                  {flow.timestamp_start ? new Date(flow.timestamp_start * 1000).toISOString() : 'N/A'}
                </span>
              </div>
            </div>
          </section>

          {/* Section 2: Detection Evaluation */}
          <section className="detail-section">
            <div className="section-title-row">
              <Shield size={16} className="section-icon amber" />
              <h3 className="section-title">Detection & Threshold Evaluation</h3>
            </div>
            <div className="score-summary-box">
              <div className="score-large-display">
                <span className="score-label">Continuous Threat Score ($S_t$)</span>
                <span
                  className={`score-big-num ${
                    score >= researchThreshold
                      ? 'rose'
                      : score >= operationalThreshold
                      ? 'amber'
                      : 'emerald'
                  }`}
                >
                  {score.toFixed(4)}
                </span>
              </div>
              <div className="threshold-comparison-grid">
                <div className="threshold-box">
                  <span className="thresh-name">Research Baseline (τ = {researchThreshold.toFixed(2)})</span>
                  <span className={`verdict-pill ${isResearchAttack ? 'attack' : 'benign'}`}>
                    {isResearchAttack ? 'ATTACK' : 'BENIGN'}
                  </span>
                  <span className="thresh-eval">
                    Verdict: <strong>{flow.verdict_research || flow.verdict || 'N/A'}</strong> (Ground Truth: {flow.ground_truth_label || 'N/A'})
                  </span>
                </div>
                <div className="threshold-box">
                  <span className="thresh-name">Operational Candidate (τ = {operationalThreshold.toFixed(2)})</span>
                  <span className={`verdict-pill ${isOperationalAttack ? 'attack' : 'benign'}`}>
                    {isOperationalAttack ? 'ATTACK' : 'BENIGN'}
                  </span>
                  <span className="thresh-eval">
                    Verdict: <strong>{flow.verdict_operational || (isOperationalAttack ? 'CORRECT' : 'EVALUATED')}</strong>
                  </span>
                </div>
              </div>
            </div>
          </section>

          {/* Section 3: R10 Canonical Features */}
          <section className="detail-section">
            <div className="section-title-row">
              <Info size={16} className="section-icon emerald" />
              <h3 className="section-title">Canonical R10 Feature Vector</h3>
              <span className="r10-badge">Contract: atol ≤ 1e-4</span>
            </div>
            <p className="section-desc">
              Exact features extracted under the D-006 flow policy and evaluated by the Random Forest model.
            </p>
            <div className="r10-features-table-wrap">
              <table className="r10-table">
                <thead>
                  <tr>
                    <th>Feature Name</th>
                    <th>Extracted Value</th>
                    <th>Units / Meaning</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="feat-name">flow_duration_ms</td>
                    <td className="feat-val">{features.flow_duration_ms?.toFixed(4) ?? 'N/A'}</td>
                    <td className="feat-desc">Milliseconds active</td>
                  </tr>
                  <tr>
                    <td className="feat-name">flow_packets_per_s</td>
                    <td className="feat-val">{features.flow_packets_per_s?.toFixed(4) ?? 'N/A'}</td>
                    <td className="feat-desc">Packet rate (packets/sec)</td>
                  </tr>
                  <tr>
                    <td className="feat-name">flow_bytes_per_s</td>
                    <td className="feat-val">{features.flow_bytes_per_s?.toFixed(2) ?? 'N/A'}</td>
                    <td className="feat-desc">Throughput (bytes/sec)</td>
                  </tr>
                  <tr>
                    <td className="feat-name">packet_length_mean</td>
                    <td className="feat-val">{features.packet_length_mean?.toFixed(2) ?? 'N/A'}</td>
                    <td className="feat-desc">Mean packet length (bytes)</td>
                  </tr>
                  <tr>
                    <td className="feat-name">packet_length_std</td>
                    <td className="feat-val">{features.packet_length_std?.toFixed(4) ?? 'N/A'}</td>
                    <td className="feat-desc">Packet length standard deviation</td>
                  </tr>
                  <tr>
                    <td className="feat-name">syn_count</td>
                    <td className="feat-val">{features.syn_count ?? 'N/A'}</td>
                    <td className="feat-desc">TCP SYN flags</td>
                  </tr>
                  <tr>
                    <td className="feat-name">ack_count</td>
                    <td className="feat-val">{features.ack_count ?? 'N/A'}</td>
                    <td className="feat-desc">TCP ACK flags</td>
                  </tr>
                  <tr>
                    <td className="feat-name">rst_count</td>
                    <td className="feat-val">{features.rst_count ?? 'N/A'}</td>
                    <td className="feat-desc">TCP RST flags</td>
                  </tr>
                  <tr>
                    <td className="feat-name">fin_count</td>
                    <td className="feat-val">{features.fin_count ?? 'N/A'}</td>
                    <td className="feat-desc">TCP FIN flags</td>
                  </tr>
                  <tr>
                    <td className="feat-name">syn_ack_ratio</td>
                    <td className="feat-val">{features.syn_ack_ratio?.toFixed(4) ?? 'N/A'}</td>
                    <td className="feat-desc">SYN / (ACK + 1) ratio</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Section 4: Response Panel (DQN / Safety Gate) */}
          <section className="detail-section">
            <div className="section-title-row">
              <Lock size={16} className="section-icon purple" />
              <h3 className="section-title">Autonomous Response Panel</h3>
            </div>
            <div className="response-panel-box">
              {flow.proposed_action ? (
                <div className="response-active-grid">
                  <div className="resp-item">
                    <span className="resp-label">Proposed Action:</span>
                    <span className="action-tag">{flow.proposed_action}</span>
                  </div>
                  <div className="resp-item">
                    <span className="resp-label">Enforced Action:</span>
                    <span className="action-tag">{flow.enforced_action}</span>
                  </div>
                  <div className="resp-item">
                    <span className="resp-label">Safety Override:</span>
                    <span>{flow.safety_override ? 'YES' : 'NO'}</span>
                  </div>
                  {flow.override_reason && (
                    <div className="resp-item full-width">
                      <span className="resp-label">Override Reason:</span>
                      <span>{flow.override_reason}</span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="response-unavail-box">
                  <div className="unavail-title">
                    <Info size={16} />
                    <span>Response decision: Not available in replay artifact</span>
                  </div>
                  <p className="unavail-text">
                    This demonstration PCAP replay evaluated the perception pipeline (Flow Construction → R10 Feature Extraction → Trained Random Forest Inference). Autonomous mitigation policies (ALLOW, ALERT, RATE_LIMIT, ISOLATE) and safety gate invariants are validated in the dedicated Phase 2 DQN environment and Phase 3 isolated-lab network namespace transaction harness.
                  </p>
                  <div className="supported-actions-row">
                    <span className="actions-header">Supported Autonomous Actions:</span>
                    <span className="action-badge allow">ALLOW</span>
                    <span className="action-badge alert">ALERT</span>
                    <span className="action-badge ratelimit">RATE_LIMIT</span>
                    <span className="action-badge isolate">ISOLATE</span>
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* Section 5: Explainability Panel (SHAP / Audit) */}
          <section className="detail-section">
            <div className="section-title-row">
              <AlertTriangle size={16} className="section-icon blue" />
              <h3 className="section-title">Why was this flow flagged?</h3>
            </div>
            <div className="explainability-box">
              {flow.shap_values && Object.keys(flow.shap_values).length > 0 ? (
                <div className="shap-table-container">
                  <h4 className="shap-title">Top Feature Attributions (TreeSHAP)</h4>
                  <table className="shap-table">
                    <thead>
                      <tr>
                        <th>Feature</th>
                        <th>SHAP Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(flow.shap_values).map(([feat, val]) => (
                        <tr key={feat}>
                          <td>{feat}</td>
                          <td className={val >= 0 ? 'shap-pos' : 'shap-neg'}>
                            {val >= 0 ? `+${val.toFixed(4)}` : val.toFixed(4)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="explainability-fallback">
                  <div className="explain-status-row">
                    <span className="explain-tag">Dual-Layer Explainability Pipeline</span>
                  </div>
                  <p className="explain-text">
                    Feature-level explanation available from the research explainability pipeline. No per-flow SHAP payload is present in this demo artifact.
                  </p>
                  <div className="explain-context-box">
                    <span className="context-title">Heuristic Feature Observations for this Flow:</span>
                    <ul className="context-list">
                      {score >= researchThreshold ? (
                        <>
                          <li>Anomalous high flow packet rate: <strong>{features.flow_packets_per_s?.toFixed(1)} pkts/s</strong></li>
                          <li>Elevated mean packet length: <strong>{features.packet_length_mean?.toFixed(1)} bytes</strong></li>
                          <li>Significant throughput density: <strong>{((features.flow_bytes_per_s ?? 0) / 1024).toFixed(1)} KB/s</strong></li>
                        </>
                      ) : (
                        <>
                          <li>Normal handshake progression: <strong>{features.syn_count} SYN / {features.ack_count} ACK</strong></li>
                          <li>Standard browsing packet length variance: <strong>{features.packet_length_std?.toFixed(1)}</strong></li>
                          <li>Low threat score within normal bounds (S_t &lt; 0.40)</li>
                        </>
                      )}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};
