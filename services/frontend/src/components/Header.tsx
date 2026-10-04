import React from 'react';
import { Shield, RefreshCw, Cpu } from './Icons';

interface HeaderProps {
  systemMode: string;
  modelIdentifier: string;
  featureContract: string;
  researchThreshold: number;
  operationalThreshold: number;
  dataSource: 'real' | 'fallback';
  isLoaded: boolean;
  isLoading: boolean;
  onLoadDemo: () => void;
  onRefresh: () => void;
  onClear: () => void;
  onToggleSource: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  systemMode,
  modelIdentifier,
  featureContract,
  researchThreshold,
  operationalThreshold,
  dataSource,
  isLoaded,
  isLoading,
  onLoadDemo,
  onRefresh,
  onClear,
  onToggleSource,
}) => {
  return (
    <header className="dashboard-header">
      <div className="header-top">
        <div className="brand-group">
          <div className="brand-icon">
            <Shield size={28} className="shield-icon" />
          </div>
          <div>
            <div className="brand-title-row">
              <h1 className="brand-title">XRL-IDARS</h1>
              <span className="status-badge ready">
                <span className="pulse-dot"></span>
                SYSTEM READY
              </span>
              <span className={`data-badge ${dataSource === 'real' ? 'real' : 'fallback'}`}>
                {dataSource === 'real' ? 'REAL ARTIFACT (replay_summary.json)' : 'DEMO DATA (FALLBACK)'}
              </span>
            </div>
            <p className="brand-subtitle">
              Explainable Reinforcement Learning Based Intrusion Detection and Autonomous Response System
            </p>
          </div>
        </div>

        <div className="header-controls">
          <button
            className="btn btn-primary"
            onClick={onLoadDemo}
            disabled={isLoading}
            title="Load demo data from results/demo/replay_summary.json"
          >
            <Cpu size={16} />
            <span>Load Demo</span>
          </button>

          <button
            className="btn btn-secondary"
            onClick={onRefresh}
            disabled={isLoading || !isLoaded}
            title="Re-read replay_summary.json"
          >
            <RefreshCw size={16} className={isLoading ? 'spinning' : ''} />
            <span>Refresh Data</span>
          </button>

          <button
            className="btn btn-outline"
            onClick={onToggleSource}
            title="Toggle between real artifact and static fallback demo data"
          >
            <span>{dataSource === 'real' ? 'Use Fallback Data' : 'Use Real JSON'}</span>
          </button>

          <button
            className="btn btn-danger-outline"
            onClick={onClear}
            disabled={!isLoaded}
            title="Clear current view"
          >
            <span>Clear View</span>
          </button>
        </div>
      </div>

      <div className="meta-strip">
        <div className="meta-item">
          <span className="meta-label">SYSTEM MODE:</span>
          <span className="meta-value highlight-cyan">{systemMode}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">MODEL:</span>
          <span className="meta-value">{modelIdentifier}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">FEATURE CONTRACT:</span>
          <span className="meta-value highlight-emerald">{featureContract}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">RESEARCH THRESHOLD:</span>
          <span className="meta-value highlight-rose">{researchThreshold.toFixed(2)}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">OPERATIONAL CANDIDATE:</span>
          <span className="meta-value highlight-amber">{operationalThreshold.toFixed(2)}</span>
        </div>
      </div>
    </header>
  );
};
