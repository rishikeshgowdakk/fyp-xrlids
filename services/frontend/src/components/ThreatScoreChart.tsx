import React from 'react';
import { FlowEvent } from '../types';

interface ThreatScoreChartProps {
  flows: FlowEvent[];
  researchThreshold: number;
  operationalThreshold: number;
  selectedFlowId: number | null;
  onSelectFlow: (flowId: number) => void;
}

export const ThreatScoreChart: React.FC<ThreatScoreChartProps> = ({
  flows,
  researchThreshold,
  operationalThreshold,
  selectedFlowId,
  onSelectFlow,
}) => {
  if (flows.length === 0) {
    return (
      <div className="chart-card">
        <div className="chart-header">
          <span className="chart-title">THREAT SCORE BY FLOW</span>
        </div>
        <div className="chart-empty">No flow events loaded</div>
      </div>
    );
  }

  // Chart coordinate space
  const svgWidth = 600;
  const svgHeight = 220;
  const paddingLeft = 45;
  const paddingRight = 25;
  const paddingTop = 30;
  const paddingBottom = 35;

  const plotWidth = svgWidth - paddingLeft - paddingRight;
  const plotHeight = svgHeight - paddingTop - paddingBottom;

  const getY = (val: number) => paddingTop + plotHeight - val * plotHeight;

  const yResearch = getY(researchThreshold);
  const yOperational = getY(operationalThreshold);

  const barWidth = Math.min(48, Math.max(24, (plotWidth / flows.length) * 0.55));
  const colStep = plotWidth / flows.length;

  return (
    <div className="chart-card">
      <div className="chart-header">
        <div>
          <span className="chart-title">THREAT SCORE DISTRIBUTION BY FLOW</span>
          <span className="chart-subtitle">Continuous RF Model Output $S_t \in [0, 1]$</span>
        </div>
        <div className="chart-legend">
          <span className="legend-item">
            <span className="legend-line research"></span>
            Research Threshold ({researchThreshold.toFixed(2)})
          </span>
          <span className="legend-item">
            <span className="legend-line operational"></span>
            Operational Candidate ({operationalThreshold.toFixed(2)})
          </span>
        </div>
      </div>

      <div className="chart-svg-container">
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="threat-chart-svg"
          preserveAspectRatio="xMidYMid meet"
        >
          {/* Background grid lines */}
          {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((tick) => {
            const y = getY(tick);
            return (
              <g key={tick} className="grid-tick">
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={svgWidth - paddingRight}
                  y2={y}
                  stroke="rgba(255, 255, 255, 0.08)"
                  strokeDasharray="2 3"
                />
                <text
                  x={paddingLeft - 8}
                  y={y + 4}
                  textAnchor="end"
                  className="chart-axis-text"
                >
                  {tick.toFixed(1)}
                </text>
              </g>
            );
          })}

          {/* Operational Candidate Threshold Line (0.40) */}
          <line
            x1={paddingLeft}
            y1={yOperational}
            x2={svgWidth - paddingRight}
            y2={yOperational}
            stroke="#f59e0b"
            strokeWidth="1.5"
            strokeDasharray="4 4"
          />
          <text
            x={svgWidth - paddingRight - 4}
            y={yOperational - 6}
            textAnchor="end"
            fill="#f59e0b"
            fontSize="10"
            fontWeight="600"
          >
            τ=0.40 Candidate
          </text>

          {/* Research Threshold Line (0.50) */}
          <line
            x1={paddingLeft}
            y1={yResearch}
            x2={svgWidth - paddingRight}
            y2={yResearch}
            stroke="#f43f5e"
            strokeWidth="1.5"
            strokeDasharray="4 4"
          />
          <text
            x={svgWidth - paddingRight - 4}
            y={yResearch - 6}
            textAnchor="end"
            fill="#f43f5e"
            fontSize="10"
            fontWeight="600"
          >
            τ=0.50 Research
          </text>

          {/* Bars for each flow */}
          {flows.map((flow, index) => {
            const xCenter = paddingLeft + index * colStep + colStep / 2;
            const xBar = xCenter - barWidth / 2;
            const score = Math.max(0, Math.min(1, flow.attack_score));
            const barH = score * plotHeight;
            const yBar = paddingTop + plotHeight - barH;
            const isSelected = selectedFlowId === flow.flow_id;

            let fillColor = '#10b981'; // Benign green (< 0.40)
            if (score >= researchThreshold) {
              fillColor = '#f43f5e'; // Attack red (>= 0.50)
            } else if (score >= operationalThreshold) {
              fillColor = '#f59e0b'; // Ambiguous candidate amber (0.40 - 0.50)
            }

            return (
              <g
                key={flow.flow_id}
                className={`chart-bar-group ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelectFlow(flow.flow_id)}
                style={{ cursor: 'pointer' }}
              >
                {/* Clickable hit area */}
                <rect
                  x={xCenter - colStep / 2}
                  y={paddingTop}
                  width={colStep}
                  height={plotHeight}
                  fill="transparent"
                />

                {/* Main bar */}
                <rect
                  x={xBar}
                  y={yBar}
                  width={barWidth}
                  height={Math.max(2, barH)}
                  rx="3"
                  fill={fillColor}
                  opacity={isSelected ? 1.0 : 0.82}
                  stroke={isSelected ? '#38bdf8' : 'none'}
                  strokeWidth={isSelected ? 2 : 0}
                  className="bar-rect"
                />

                {/* Score label on top of bar */}
                <text
                  x={xCenter}
                  y={yBar - 6}
                  textAnchor="middle"
                  className="bar-value-text"
                  fill={isSelected ? '#38bdf8' : '#e2e8f0'}
                  fontSize="11"
                  fontWeight="600"
                >
                  {score.toFixed(3)}
                </text>

                {/* X-axis label */}
                <text
                  x={xCenter}
                  y={svgHeight - 12}
                  textAnchor="middle"
                  className="chart-axis-text flow-label"
                  fill={isSelected ? '#38bdf8' : '#94a3b8'}
                  fontWeight={isSelected ? '700' : '500'}
                  fontSize="11"
                >
                  F#{flow.flow_id}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="chart-footer-note">
        Click any flow bar to inspect R10 features, threshold comparison, and classification evidence.
      </div>
    </div>
  );
};
