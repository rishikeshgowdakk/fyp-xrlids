import React from 'react';
import { FlowEvent } from '../types';

interface NetworkSummaryProps {
  flows: FlowEvent[];
}

export const NetworkSummary: React.FC<NetworkSummaryProps> = ({ flows }) => {
  const srcIps = Array.from(new Set(flows.map((f) => f.src_endpoint.split(':')[0])));
  const dstIps = Array.from(new Set(flows.map((f) => f.dst_endpoint.split(':')[0])));

  const tcpCount = flows.filter((f) => f.protocol_name.toUpperCase() === 'TCP').length;
  const udpCount = flows.filter((f) => f.protocol_name.toUpperCase() === 'UDP').length;
  const otherCount = flows.length - tcpCount - udpCount;

  const totalPackets = flows.reduce((acc, f) => acc + (f.packet_count || 0), 0);
  const totalDurationMs = flows.reduce((acc, f) => acc + (f.duration_ms || 0), 0);

  return (
    <div className="network-summary-card">
      <div className="summary-header">
        <span className="summary-title">NETWORK TOPOLOGY & TRAFFIC SUMMARY</span>
      </div>

      <div className="summary-metrics-grid">
        <div className="summary-box">
          <span className="summary-box-label">Unique Source IPs</span>
          <span className="summary-box-val highlight-cyan">{srcIps.length}</span>
          <div className="summary-tags">
            {srcIps.map((ip) => (
              <span key={ip} className="endpoint-tag" title={ip}>
                {ip}
              </span>
            ))}
          </div>
        </div>

        <div className="summary-box">
          <span className="summary-box-label">Unique Destination IPs</span>
          <span className="summary-box-val highlight-purple">{dstIps.length}</span>
          <div className="summary-tags">
            {dstIps.map((ip) => (
              <span key={ip} className="endpoint-tag dst" title={ip}>
                {ip}
              </span>
            ))}
          </div>
        </div>

        <div className="summary-box">
          <span className="summary-box-label">Protocol Breakdown</span>
          <div className="protocol-bar-container">
            <div
              className="proto-segment tcp"
              style={{ width: `${flows.length ? (tcpCount / flows.length) * 100 : 0}%` }}
              title={`TCP: ${tcpCount} flows`}
            ></div>
            <div
              className="proto-segment udp"
              style={{ width: `${flows.length ? (udpCount / flows.length) * 100 : 0}%` }}
              title={`UDP: ${udpCount} flows`}
            ></div>
          </div>
          <div className="protocol-legend-row">
            <span>TCP: <strong>{tcpCount}</strong> ({flows.length ? Math.round((tcpCount / flows.length) * 100) : 0}%)</span>
            <span>UDP: <strong>{udpCount}</strong> ({flows.length ? Math.round((udpCount / flows.length) * 100) : 0}%)</span>
            {otherCount > 0 && <span>Other: <strong>{otherCount}</strong></span>}
          </div>
        </div>

        <div className="summary-box">
          <span className="summary-box-label">Aggregated Volume</span>
          <div className="summary-volume-row">
            <div>
              <span className="vol-sub">Packets</span>
              <span className="vol-val">{totalPackets}</span>
            </div>
            <div>
              <span className="vol-sub">Total Duration</span>
              <span className="vol-val">{(totalDurationMs / 1000).toFixed(2)}s</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
