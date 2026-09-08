import { useEffect, useMemo, useState } from 'react';
import { api, type Asset } from '../lib/api';

export function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [search, setSearch] = useState('');

  useEffect(() => {
    api
      .listAssets()
      .then(setAssets)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load assets'));
  }, []);

  const types = useMemo(() => ['ALL', ...new Set(assets.map((a) => a.type))], [assets]);

  const filtered = assets.filter(
    (a) =>
      (typeFilter === 'ALL' || a.type === typeFilter) &&
      (search === '' || a.name.toLowerCase().includes(search.toLowerCase()))
  );

  if (error) {
    return (
      <div className="rounded-md border border-slate-800 bg-slate-900 p-6 text-slate-400">
        {error.includes('404') ? (
          <>No scan has been run yet. Go to the Dashboard and click "Run Scan" first.</>
        ) : (
          error
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-slate-100">Assets</h1>

      <div className="flex gap-3">
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
        >
          {types.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name..."
          className="flex-1 rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600"
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-left text-slate-400">
            <tr>
              <th className="px-4 py-2 font-medium">Name</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Region</th>
              <th className="px-4 py-2 font-medium">Public</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {filtered.map((a) => (
              <tr key={a.id} className="bg-slate-950/50 hover:bg-slate-900">
                <td className="px-4 py-2 font-mono text-xs text-slate-200">{a.name}</td>
                <td className="px-4 py-2 text-slate-400">{a.type}</td>
                <td className="px-4 py-2 text-slate-400">{a.region ?? '-'}</td>
                <td className="px-4 py-2">
                  {a.public ? (
                    <span className="text-red-400">Yes</span>
                  ) : (
                    <span className="text-slate-500">No</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p className="p-4 text-center text-sm text-slate-500">No assets match this filter.</p>
        )}
      </div>
    </div>
  );
}
