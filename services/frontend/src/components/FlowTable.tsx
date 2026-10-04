import React, { useState, useMemo } from 'react';
import { FlowEvent, ProtocolFilter, VerdictFilter, SortKey, SortDirection } from '../types';
import { Search, Filter, ArrowUpDown } from './Icons';

interface FlowTableProps {
  flows: FlowEvent[];
  researchThreshold: number;
  operationalThreshold: number;
  selectedFlowId: number | null;
  onSelectFlow: (flowId: number) => void;
}

export const FlowTable: React.FC<FlowTableProps> = ({
  flows,
  researchThreshold,
  operationalThreshold,
  selectedFlowId,
  onSelectFlow,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<ProtocolFilter>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>('ALL');
  const [sortKey, setSortKey] = useState<SortKey>('flow_id');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDirection('asc');
    }
  };

  const filteredAndSortedFlows = useMemo(() => {
    return flows
      .filter((flow) => {
        // Protocol filter
        if (protocolFilter !== 'ALL' && flow.protocol_name.toUpperCase() !== protocolFilter) {
          return false;
        }

        // Verdict filter (based on research prediction or attack_score >= researchThreshold)
        if (verdictFilter !== 'ALL') {
          const isAttack = flow.pred_research_label === 'ATTACK' || flow.attack_score >= researchThreshold;
          if (verdictFilter === 'ATTACK' && !isAttack) return false;
          if (verdictFilter === 'BENIGN' && isAttack) return false;
        }

        // Search term
        if (searchTerm.trim() !== '') {
          const term = searchTerm.toLowerCase();
          const matches =
            flow.flow_id.toString().includes(term) ||
            flow.src_endpoint.toLowerCase().includes(term) ||
            flow.dst_endpoint.toLowerCase().includes(term) ||
            flow.protocol_name.toLowerCase().includes(term) ||
            flow.prediction_label.toLowerCase().includes(term);
          if (!matches) return false;
        }

        return true;
      })
      .sort((a, b) => {
        let valA: number | string = a[sortKey as keyof FlowEvent] as number | string;
        let valB: number | string = b[sortKey as keyof FlowEvent] as number | string;

        if (sortKey === 'src_endpoint') {
          valA = a.src_endpoint;
          valB = b.src_endpoint;
        } else if (sortKey === 'dst_endpoint') {
          valA = a.dst_endpoint;
          valB = b.dst_endpoint;
        }

        if (valA == null) return 1;
        if (valB == null) return -1;

        if (typeof valA === 'number' && typeof valB === 'number') {
          return sortDirection === 'asc' ? valA - valB : valB - valA;
        }

        const strA = String(valA).toLowerCase();
        const strB = String(valB).toLowerCase();
        return sortDirection === 'asc' ? strA.localeCompare(strB) : strB.localeCompare(strA);
      });
  }, [flows, protocolFilter, verdictFilter, searchTerm, sortKey, sortDirection, researchThreshold]);

  const formatTimestamp = (ts: number) => {
    if (!ts) return 'N/A';
    const date = new Date(ts * 1000);
    return date.toISOString().slice(11, 19);
  };

  return (
    <div className="table-container-card">
      <div className="table-controls-bar">
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search Flow ID, IP, port, protocol..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button className="search-clear-btn" onClick={() => setSearchTerm('')}>
              ×
            </button>
          )}
        </div>

        <div className="filter-group">
          <div className="filter-item">
            <Filter size={14} className="filter-icon" />
            <span className="filter-label">Proto:</span>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value as ProtocolFilter)}
              className="filter-select"
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>
          </div>

          <div className="filter-item">
            <span className="filter-label">Verdict:</span>
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value as VerdictFilter)}
              className="filter-select"
            >
              <option value="ALL">All Verdicts</option>
              <option value="BENIGN">Benign</option>
              <option value="ATTACK">Attack</option>
            </select>
          </div>

          <div className="table-count-badge">
            Showing {filteredAndSortedFlows.length} of {flows.length} flows
          </div>
        </div>
      </div>

      <div className="table-responsive-wrapper">
        <table className="flow-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('flow_id')} className="sortable-th">
                <span>Flow ID</span>
                <ArrowUpDown size={12} />
              </th>
              <th onClick={() => handleSort('timestamp_start')} className="sortable-th">
                <span>Timestamp</span>
                <ArrowUpDown size={12} />
              </th>
              <th onClick={() => handleSort('src_endpoint')} className="sortable-th">
                <span>Source IP</span>
                <ArrowUpDown size={12} />
              </th>
              <th>Src Port</th>
              <th onClick={() => handleSort('dst_endpoint')} className="sortable-th">
                <span>Destination IP</span>
                <ArrowUpDown size={12} />
              </th>
              <th>Dst Port</th>
              <th onClick={() => handleSort('protocol_name')} className="sortable-th">
                <span>Protocol</span>
                <ArrowUpDown size={12} />
              </th>
              <th onClick={() => handleSort('packet_count')} className="sortable-th">
                <span>Packets</span>
                <ArrowUpDown size={12} />
              </th>
              <th onClick={() => handleSort('duration_ms')} className="sortable-th">
                <span>Duration</span>
                <ArrowUpDown size={12} />
              </th>
              <th onClick={() => handleSort('attack_score')} className="sortable-th">
                <span>Threat Score</span>
                <ArrowUpDown size={12} />
              </th>
              <th onClick={() => handleSort('prediction_label')} className="sortable-th">
                <span>Verdict (τ=0.50)</span>
                <ArrowUpDown size={12} />
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredAndSortedFlows.length === 0 ? (
              <tr>
                <td colSpan={11} className="empty-table-cell">
                  No matching flows found in current replay dataset.
                </td>
              </tr>
            ) : (
              filteredAndSortedFlows.map((flow) => {
                const [srcIp, srcPort] = flow.src_endpoint.split(':');
                const [dstIp, dstPort] = flow.dst_endpoint.split(':');
                const isSelected = selectedFlowId === flow.flow_id;
                const score = flow.attack_score ?? 0;

                // Threshold-aware classifications
                const isResearchAttack =
                  flow.pred_research_label === 'ATTACK' || score >= researchThreshold;
                const isOperationalAttack =
                  flow.pred_operational_label === 'ATTACK' || score >= operationalThreshold;

                let scoreClass = 'score-low';
                if (score >= researchThreshold) {
                  scoreClass = 'score-high';
                } else if (score >= operationalThreshold) {
                  scoreClass = 'score-mid';
                }

                return (
                  <tr
                    key={flow.flow_id}
                    className={`flow-row ${isSelected ? 'row-selected' : ''}`}
                    onClick={() => onSelectFlow(flow.flow_id)}
                  >
                    <td className="cell-flow-id">
                      <span className="flow-id-badge">#{flow.flow_id}</span>
                    </td>
                    <td className="cell-mono text-muted">{formatTimestamp(flow.timestamp_start)}</td>
                    <td className="cell-mono highlight-src">{srcIp}</td>
                    <td className="cell-mono text-muted">{srcPort}</td>
                    <td className="cell-mono highlight-dst">{dstIp}</td>
                    <td className="cell-mono text-muted">{dstPort}</td>
                    <td>
                      <span className={`proto-badge proto-${flow.protocol_name.toLowerCase()}`}>
                        {flow.protocol_name}
                      </span>
                    </td>
                    <td className="cell-numeric">{flow.packet_count}</td>
                    <td className="cell-numeric">{flow.duration_ms.toFixed(1)} ms</td>
                    <td>
                      <div className="threat-score-cell">
                        <div className="score-bar-bg">
                          <div
                            className={`score-bar-fill ${scoreClass}`}
                            style={{ width: `${Math.min(100, score * 100)}%` }}
                          ></div>
                        </div>
                        <span className={`score-value ${scoreClass}`}>{score.toFixed(4)}</span>
                      </div>
                    </td>
                    <td>
                      <div className="verdict-cell-group">
                        <span className={`verdict-badge ${isResearchAttack ? 'attack' : 'benign'}`}>
                          {isResearchAttack ? 'ATTACK' : 'BENIGN'}
                        </span>
                        {/* Note divergence between research and candidate if any */}
                        {!isResearchAttack && isOperationalAttack && (
                          <span
                            className="candidate-flag-badge"
                            title="Flagged as ATTACK at operational threshold (τ=0.40)"
                          >
                            τ=0.40 Flag
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <div className="table-caption-bar">
        <span>Click on any flow row to inspect detailed R10 features, policy response status, and explainability.</span>
      </div>
    </div>
  );
};
