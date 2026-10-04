import React from 'react';

export const PipelineDiagram: React.FC = () => {
  const steps = [
    { name: 'PACKET', sub: 'PCAP Ingest', active: true, desc: 'data/demo/sample_traffic.pcap' },
    { name: 'FLOW', sub: 'D-006 Policy', active: true, desc: '6 Bidirectional Flows' },
    { name: 'R10 FEATURES', sub: 'Canonical Contract', active: true, desc: '10 Features (atol ≤ 1e-4)' },
    { name: 'DETECTOR', sub: 'Random Forest', active: true, desc: 'Trained Model (F1: 0.9512)' },
    { name: 'THREAT SCORE', sub: 'S_t ∈ [0, 1]', active: true, desc: 'Scores: 0.0001 → 0.5399' },
    { name: 'DQN RESPONSE', sub: 'Offline Research', active: false, desc: 'PER Policy (Phase 2)' },
    { name: 'SAFETY GATE', sub: 'Offline Lab', active: false, desc: 'Invariant Gate (Phase 3)' },
    { name: 'AUDIT / ROLLBACK', sub: 'Offline Lab', active: false, desc: 'Netns Transactions' },
  ];

  return (
    <div className="pipeline-section">
      <div className="pipeline-header">
        <span className="pipeline-title">SYSTEM PIPELINE EXECUTION TRACE</span>
        <span className="pipeline-note">
          Stages 1–5 evaluated in current replay artifact. Stages 6–8 validated in laboratory transaction harness.
        </span>
      </div>
      <div className="pipeline-diagram">
        {steps.map((step, idx) => (
          <React.Fragment key={step.name}>
            <div className={`pipeline-node ${step.active ? 'active' : 'inactive'}`}>
              <div className="pipeline-node-badge">
                {step.active ? 'EVALUATED' : 'OFFLINE HARNESS'}
              </div>
              <div className="pipeline-node-name">{step.name}</div>
              <div className="pipeline-node-sub">{step.sub}</div>
              <div className="pipeline-node-desc">{step.desc}</div>
            </div>
            {idx < steps.length - 1 && (
              <div className="pipeline-connector">
                <span className="connector-arrow">→</span>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
