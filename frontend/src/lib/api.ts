// Phase 11 — API client.
//
// Thin typed wrapper around the endpoints backend/main.py actually
// exposes today (Phase 8/10). Deliberately does NOT invent endpoints
// for features that don't exist yet (findings list, MITRE, what-if) —
// those pages are stubbed in the UI with a "not implemented yet" state
// instead of fake data, see src/pages/*.

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

  createScanAsync: (region = 'us-east-1', crownJewelIds: string[] = []) =>
    request<ScanSummary>('/scans/async', {
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
};
