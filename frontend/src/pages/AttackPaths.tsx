import { useEffect, useState } from 'react';
import { api, type AttackPath } from '../lib/api';
import { SeverityBadge } from '../components/SeverityBadge';

export function AttackPaths() {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    api
      .listAttackPaths()
      .then(setPaths)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load attack paths'));
  }, []);

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
      <h1 className="text-2xl font-bold text-slate-100">Attack Paths</h1>
      <p className="text-sm text-slate-500">
        Ranked by risk score. "Potential" status means at least one edge in the path has evidence
        confidence below the threshold.
      </p>

      {paths.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-6 text-center text-slate-500">
          No attack paths found — either the account is clean, or no entry points reach any of the
          declared/default targets.
        </div>
      ) : (
        <div className="space-y-2">
          {paths.map((p) => (
            <div key={p.id} className="rounded-lg border border-slate-800 bg-slate-900">
              <button
                onClick={() => setExpanded(expanded === p.id ? null : p.id)}
                className="flex w-full items-center justify-between px-4 py-3 text-left"
              >
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={p.severity} />
                  <span className="font-mono text-xs text-slate-300">
                    {p.entry} → {p.target}
                  </span>
                  {p.status === 'potential_path' && (
                    <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-500">
                      POTENTIAL
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-4 text-xs text-slate-500">
                  <span>Risk {p.risk_score}/100</span>
                  <span>Confidence {(p.confidence * 100).toFixed(0)}%</span>
                  <span>{p.hop_count} hops</span>
                </div>
              </button>

              {expanded === p.id && (
                <div className="border-t border-slate-800 px-4 py-3">
                  <ol className="space-y-1.5">
                    {p.steps.map((s, i) => (
                      <li key={i} className="flex items-center gap-2 font-mono text-xs">
                        <span className="text-slate-600">{i + 1}.</span>
                        <span className="text-slate-300">{s.source}</span>
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-400">
                          {s.edge_type}
                        </span>
                        <span className="text-slate-500">→</span>
                        <span className="text-slate-300">{s.target}</span>
                        <span className="ml-auto text-slate-600">
                          conf {(s.confidence * 100).toFixed(0)}%
                        </span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
