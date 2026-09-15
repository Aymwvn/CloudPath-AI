export interface ScanSummary {
  scan_id: string;
  account_id: string;
  status: string;
  asset_count: number;
  relationship_count: number;
  errors: string[];
}

export interface Asset {
  id: string;
  type: string;
  name: string;
  public: boolean;
  region: string | null;
}

export interface AttackPathStep {
  source: string;
  target: string;
  edge_type: string;
  confidence: number;
}

export interface AttackPath {
  id: string;
  entry: string;
  target: string;
  status: string;
  risk_score: number;
  severity: string;
  confidence: number;
  hop_count: number;
  steps: AttackPathStep[];
}

export interface Statistics {
  node_count: number;
  edge_count: number;
  node_types: Record<string, number>;
  edge_types: Record<string, number>;
  attack_path_count: number;
  critical_path_count: number;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  public: boolean;
  max_severity: string | null;
  on_attack_path: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  confidence: number;
  max_severity: string | null;
  on_attack_path: boolean;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    node_count: number;
    edge_count: number;
    attack_path_count: number;
    nodes_on_attack_paths: number;
  };
}

const BASE = '/api/v1';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
  createScan: (region = 'us-east-1', crownJewelIds: string[] = []) =>
    request<ScanSummary>('/scans', {
      method: 'POST',
      body: JSON.stringify({ region, crown_jewel_ids: crownJewelIds }),
    }),

  getScan: (scanId: string) => request<ScanSummary>(`/scans/${scanId}`),

  listAssets: (scanId?: string) =>
    request<Asset[]>(`/assets${scanId ? `?scan_id=${scanId}` : ''}`),

  listAttackPaths: (scanId?: string) =>
    request<AttackPath[]>(`/attack-paths${scanId ? `?scan_id=${scanId}` : ''}`),

  getStatistics: (scanId?: string) =>
    request<Statistics>(`/statistics${scanId ? `?scan_id=${scanId}` : ''}`),

  // New: full graph payload for the interactive attack graph page.
  getGraph: (scanId?: string) =>
    request<GraphPayload>(`/graph${scanId ? `?scan_id=${scanId}` : ''}`),
};
