import React, { useState, useEffect, useCallback } from 'react';
import { ReplaySummary, FlowEvent } from './types';
import { fallbackDemoData } from './data/demoData';
import { Header } from './components/Header';
import { PipelineDiagram } from './components/PipelineDiagram';
import { KpiCards } from './components/KpiCards';
import { ThreatScoreChart } from './components/ThreatScoreChart';
import { NetworkSummary } from './components/NetworkSummary';
import { FlowTable } from './components/FlowTable';
import { FlowDetailPanel } from './components/FlowDetailPanel';
import { Shield } from './components/Icons';

export const App: React.FC = () => {
  const [summary, setSummary] = useState<ReplaySummary | null>(fallbackDemoData);
  const [dataSource, setDataSource] = useState<'real' | 'fallback'>('real');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [selectedFlowId, setSelectedFlowId] = useState<number | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const loadRealSummary = useCallback(async () => {
    setIsLoading(true);
    setStatusMessage('Loading demo replay artifact (replay_summary.json)...');
    try {
      const response = await fetch(`/replay_summary.json?t=${Date.now()}`);
      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}: Failed to fetch replay_summary.json`);
      }
      const data: ReplaySummary = await response.json();
      setSummary(data);
      setDataSource('real');
      setStatusMessage('Loaded results/demo/replay_summary.json successfully.');
    } catch (err) {
      console.warn('Could not fetch real replay_summary.json, falling back to static demoData:', err);
      setSummary(fallbackDemoData);
      setDataSource('fallback');
      setStatusMessage('Real JSON unavailable; using local static fallback demo data.');
    } finally {
      setIsLoading(false);
      setTimeout(() => setStatusMessage(null), 4000);
    }
  }, []);

  // Attempt to load real summary on initial mount
  useEffect(() => {
    loadRealSummary();
  }, [loadRealSummary]);

  const handleToggleSource = () => {
    if (dataSource === 'real') {
      setSummary(fallbackDemoData);
      setDataSource('fallback');
      setStatusMessage('Switched to static demoData fallback.');
    } else {
      loadRealSummary();
    }
    setTimeout(() => setStatusMessage(null), 3000);
  };

  const handleClear = () => {
    setSummary(null);
    setSelectedFlowId(null);
    setStatusMessage('View cleared.');
    setTimeout(() => setStatusMessage(null), 3000);
  };

  const selectedFlow: FlowEvent | null =
    summary?.flow_events?.find((f) => f.flow_id === selectedFlowId) || null;

  return (
    <div className="app-container">
      <Header
        systemMode="PCAP REPLAY / DEMO"
        modelIdentifier="Random Forest (EXP-P1-CIC2017-R10-001)"
        featureContract="R10 (10 Features)"
        researchThreshold={summary?.research_threshold ?? 0.5}
        operationalThreshold={summary?.operational_candidate_threshold ?? 0.4}
        dataSource={dataSource}
        isLoaded={summary !== null}
        isLoading={isLoading}
        onLoadDemo={loadRealSummary}
        onRefresh={loadRealSummary}
        onClear={handleClear}
        onToggleSource={handleToggleSource}
      />

      <PipelineDiagram />

      {statusMessage && (
        <div className="status-toast" style={{
          background: 'rgba(6, 182, 212, 0.15)',
          borderBottom: '1px solid var(--accent-cyan)',
          color: 'var(--accent-cyan)',
          padding: '8px 28px',
          fontSize: '12px',
          fontFamily: 'var(--font-mono)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{statusMessage}</span>
          <button
            onClick={() => setStatusMessage(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer' }}
          >
            ×
          </button>
        </div>
      )}

      <main className="main-content">
        <KpiCards summary={summary} />

        <div className="dashboard-grid">
          <div className="grid-main">
            <FlowTable
              flows={summary?.flow_events || []}
              researchThreshold={summary?.research_threshold ?? 0.5}
              operationalThreshold={summary?.operational_candidate_threshold ?? 0.4}
              selectedFlowId={selectedFlowId}
              onSelectFlow={(id) => setSelectedFlowId(id)}
            />
          </div>

          <div className="grid-sidebar">
            <ThreatScoreChart
              flows={summary?.flow_events || []}
              researchThreshold={summary?.research_threshold ?? 0.5}
              operationalThreshold={summary?.operational_candidate_threshold ?? 0.4}
              selectedFlowId={selectedFlowId}
              onSelectFlow={(id) => setSelectedFlowId(id)}
            />

            <NetworkSummary flows={summary?.flow_events || []} />
          </div>
        </div>
      </main>

      {/* Selected Flow Inspection Drawer */}
      <FlowDetailPanel
        flow={selectedFlow}
        researchThreshold={summary?.research_threshold ?? 0.5}
        operationalThreshold={summary?.operational_candidate_threshold ?? 0.4}
        onClose={() => setSelectedFlowId(null)}
      />

      <footer className="dashboard-footer">
        <div className="footer-left">
          <Shield size={14} className="cyan" />
          <span>XRL-IDARS v1.0.0 — Offline Laboratory & Demonstration UI</span>
        </div>
        <div className="footer-right">
          <span>Read-Only Visualization</span>
          <span>Zero Network Mutations Guaranteed</span>
        </div>
      </footer>
    </div>
  );
};
