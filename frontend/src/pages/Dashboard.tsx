import { useState } from 'react';
import { api, type Statistics } from '../lib/api';

export function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [stats, setStats] = useState<Statistics | null>(null);

  async function runScan() {
    setLoading(true);
    setError(null);
    try {
      const summary = await api.createScan();
      setScanId(summary.scan_id);
      const s = await api.getStatistics(summary.scan_id);
      setStats(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
        <button
          onClick={runScan}
          disabled={loading}
          className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          {loading ? 'Scanning...' : 'Run Scan'}
        </button>
      </div>

      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
          {error}. Check that the backend is running and AWS credentials are configured.
        </div>
      )}

      {!stats && !loading && !error && (
        <p className="text-slate-400">
          No scan yet. Click "Run Scan" to discover assets and attack paths in the configured
          AWS account.
        </p>
      )}

      {stats && (
        <>
          <p className="text-sm text-slate-500">Scan ID: {scanId}</p>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatCard label="Assets" value={stats.node_count} />
            <StatCard label="Relationships" value={stats.edge_count} />
            <StatCard label="Attack Paths" value={stats.attack_path_count} />
            <StatCard label="Critical Paths" value={stats.critical_path_count} accent="text-red-400" />
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <BreakdownCard title="Assets by Type" data={stats.node_types} />
            <BreakdownCard title="Relationships by Type" data={stats.edge_types} />
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className={`text-3xl font-bold ${accent ?? 'text-slate-100'}`}>{value}</div>
      <div className="text-sm text-slate-500">{label}</div>
    </div>
  );
}

function BreakdownCard({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-3 text-sm font-semibold text-slate-300">{title}</h2>
      {entries.length === 0 ? (
        <p className="text-sm text-slate-500">No data</p>
      ) : (
        <ul className="space-y-1.5">
          {entries.map(([key, count]) => (
            <li key={key} className="flex justify-between text-sm">
              <span className="text-slate-400">{key}</span>
              <span className="font-medium text-slate-200">{count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
