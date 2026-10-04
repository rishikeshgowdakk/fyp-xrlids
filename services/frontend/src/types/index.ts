export interface R10Features {
  flow_duration_ms: number;
  flow_packets_per_s: number;
  flow_bytes_per_s: number;
  packet_length_mean: number;
  packet_length_std: number;
  syn_count: number;
  ack_count: number;
  rst_count: number;
  fin_count: number;
  syn_ack_ratio: number;
}

export interface FlowEvent {
  flow_id: number;
  timestamp_start: number;
  protocol_name: string;
  src_endpoint: string;
  dst_endpoint: string;
  packet_count: number;
  duration_ms: number;
  attack_score: number;
  confidence: number;
  prediction_class: number;
  prediction_label: 'BENIGN' | 'ATTACK';
  verdict: 'CORRECT' | 'INCORRECT' | string;
  pred_research_class: number;
  pred_research_label: 'BENIGN' | 'ATTACK';
  verdict_research: string;
  pred_operational_class: number;
  pred_operational_label: 'BENIGN' | 'ATTACK';
  verdict_operational: string;
  ground_truth_class: number;
  ground_truth_label: 'BENIGN' | 'ATTACK';
  features: R10Features;

  // Optional response and explainability fields
  proposed_action?: 'ALLOW' | 'ALERT' | 'RATE_LIMIT' | 'ISOLATE';
  enforced_action?: 'ALLOW' | 'ALERT' | 'RATE_LIMIT' | 'ISOLATE';
  safety_override?: boolean;
  override_reason?: string;
  shap_values?: Record<string, number>;
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface Metrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  fpr?: number;
  fnr?: number;
}

export interface ReplaySummary {
  run_timestamp: string;
  pcap_file: string;
  model_identifier: string;
  research_threshold: number;
  operational_candidate_threshold: number;
  threshold: number;
  total_packets: number;
  total_flows: number;
  evaluated_flows: number;
  confusion_matrix_research: ConfusionMatrix;
  metrics_research: Metrics;
  confusion_matrix_operational: ConfusionMatrix;
  metrics_operational: Metrics;
  confusion_matrix?: ConfusionMatrix;
  metrics?: Metrics;
  flow_events: FlowEvent[];
}

export type ProtocolFilter = 'ALL' | 'TCP' | 'UDP';
export type VerdictFilter = 'ALL' | 'BENIGN' | 'ATTACK';

export type SortKey =
  | 'flow_id'
  | 'timestamp_start'
  | 'src_endpoint'
  | 'dst_endpoint'
  | 'protocol_name'
  | 'packet_count'
  | 'duration_ms'
  | 'attack_score'
  | 'prediction_label';

export type SortDirection = 'asc' | 'desc';
