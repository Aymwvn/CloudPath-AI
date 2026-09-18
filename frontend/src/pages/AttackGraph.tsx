import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { api, type GraphPayload } from '../lib/api';
import { layoutGraph, SEVERITY_COLORS, TYPE_COLORS } from '../lib/graphLayout';

export function AttackGraph() {
  const [payload, setPayload] = useState<GraphPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [showOnlyAttackPaths, setShowOnlyAttackPaths] = useState(false);

  useEffect(() => {
    api
      .getGraph()
      .then(setPayload)
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load graph'));
  }, []);

  const filteredPayload = useMemo(() => {
    if (!payload) return null;
    if (!showOnlyAttackPaths) return payload;
    return {
      ...payload,
      nodes: payload.nodes.filter((n) => n.on_attack_path),
      edges: payload.edges.filter((e) => e.on_attack_path),
    };
  }, [payload, showOnlyAttackPaths]);

  const { nodes: laidOutNodes, edges: laidOutEdges } = useMemo(() => {
    if (!filteredPayload) return { nodes: [], edges: [] };
    return layoutGraph(filteredPayload.nodes, filteredPayload.edges);
  }, [filteredPayload]);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>(laidOutNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(laidOutEdges);

  useEffect(() => {
    setNodes(laidOutNodes);
    setEdges(laidOutEdges);
  }, [laidOutNodes, laidOutEdges, setNodes, setEdges]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNodeId(node.id);
    setSelectedEdgeId(null);
  }, []);

  const onEdgeClick = useCallback((_: React.MouseEvent, edge: Edge) => {
    setSelectedEdgeId(edge.id);
    setSelectedNodeId(null);
  }, []);

  const selectedNodeDetail = payload?.nodes.find((n) => n.id === selectedNodeId) ?? null;
  const relatedEdges = payload?.edges.filter(
    (e) => e.source === selectedNodeId || e.target === selectedNodeId
  );
  const selectedEdgeDetail = payload?.edges.find((e) => e.id === selectedEdgeId) ?? null;

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

  if (!payload) {
    return <p className="text-slate-400">Loading graph...</p>;
  }

  return (
    <div className="flex h-[calc(100vh-4rem)] gap-4">
      <div className="flex flex-1 flex-col gap-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Attack Graph</h1>
            <p className="text-sm text-slate-500">
              {payload.stats.node_count} assets, {payload.stats.edge_count} relationships,{' '}
              {payload.stats.attack_path_count} attack paths found
              {payload.stats.attack_path_count > 0 && (
                <> ({payload.stats.nodes_on_attack_paths} assets involved)</>
              )}
            </p>
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={showOnlyAttackPaths}
              onChange={(e) => setShowOnlyAttackPaths(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900"
            />
            Show only attack paths
          </label>
        </div>

        <div className="flex-1 overflow-hidden rounded-lg border border-slate-800 bg-slate-950">
          {nodes.length === 0 ? (
            <div className="flex h-full items-center justify-center text-slate-500">
              {showOnlyAttackPaths
                ? 'No attack paths found — try unchecking the filter to see the full environment.'
                : 'No assets to display.'}
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              onEdgeClick={onEdgeClick}
              fitView
              colorMode="dark"
            >
              <Background color="#1e293b" gap={16} />
              <Controls />
              <MiniMap
                nodeColor={(n) => (n.style?.borderColor as string) || '#475569'}
                maskColor="rgba(15, 23, 42, 0.7)"
                style={{ background: '#0f172a' }}
              />
            </ReactFlow>
          )}
        </div>

        <Legend />
      </div>

      {selectedNodeDetail && (
        <aside className="w-72 shrink-0 overflow-y-auto rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Asset Detail</h2>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="text-slate-500 hover:text-slate-300"
            >
              ✕
            </button>
          </div>
          <dl className="space-y-2 text-xs">
            <Detail label="ID" value={selectedNodeDetail.id} mono />
            <Detail label="Type" value={selectedNodeDetail.type} />
            <Detail label="Name" value={selectedNodeDetail.label} />
            <Detail label="Public" value={selectedNodeDetail.public ? 'Yes' : 'No'} />
            <Detail label="On attack path" value={selectedNodeDetail.on_attack_path ? 'Yes' : 'No'} />
            {selectedNodeDetail.max_severity && (
              <Detail label="Max severity" value={selectedNodeDetail.max_severity} />
            )}
          </dl>

          {relatedEdges && relatedEdges.length > 0 && (
            <div className="mt-4">
              <h3 className="mb-2 text-xs font-semibold text-slate-400">
                Relationships ({relatedEdges.length}) — click one on the graph for full detail
              </h3>
              <ul className="space-y-1.5">
                {relatedEdges.map((e) => (
                  <li key={e.id} className="rounded bg-slate-800/50 p-2 font-mono text-[10px] text-slate-400">
                    <div>{e.type}</div>
                    <div className="text-slate-500">
                      {e.source === selectedNodeId ? '→ ' + e.target : '← ' + e.source}
                    </div>
                    <div className="text-slate-600">conf {(e.confidence * 100).toFixed(0)}%</div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </aside>
      )}

      {selectedEdgeDetail && (
        <aside className="w-72 shrink-0 overflow-y-auto rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Relationship Detail</h2>
            <button
              onClick={() => setSelectedEdgeId(null)}
              className="text-slate-500 hover:text-slate-300"
            >
              ✕
            </button>
          </div>
          <dl className="space-y-2 text-xs">
            <Detail label="Type" value={selectedEdgeDetail.type} />
            <Detail label="Source" value={selectedEdgeDetail.source} mono />
            <Detail label="Target" value={selectedEdgeDetail.target} mono />
            <Detail label="Confidence" value={`${(selectedEdgeDetail.confidence * 100).toFixed(0)}%`} />
            <Detail label="On attack path" value={selectedEdgeDetail.on_attack_path ? 'Yes' : 'No'} />
            {selectedEdgeDetail.max_severity && (
              <Detail label="Max severity" value={selectedEdgeDetail.max_severity} />
            )}
          </dl>

          <div className="mt-4">
            <h3 className="mb-2 text-xs font-semibold text-slate-400">Evidence</h3>
            {Object.keys(selectedEdgeDetail.evidence).length === 0 ? (
              <p className="text-[11px] text-slate-600">No evidence recorded for this relationship.</p>
            ) : (
              <pre className="overflow-x-auto rounded bg-slate-800/50 p-2 text-[10px] text-slate-400">
                {JSON.stringify(selectedEdgeDetail.evidence, null, 2)}
              </pre>
            )}
          </div>
        </aside>
      )}
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-slate-500">{label}</dt>
      <dd className={`text-slate-200 ${mono ? 'break-all font-mono' : ''}`}>{value}</dd>
    </div>
  );
}

function Legend() {
  const severityEntries = Object.entries(SEVERITY_COLORS);
  const typeEntries = Object.entries(TYPE_COLORS);
  return (
    <div className="flex flex-wrap gap-x-6 gap-y-2 rounded-lg border border-slate-800 bg-slate-900 p-3 text-[11px]">
      <div className="flex items-center gap-3">
        <span className="text-slate-500">Attack path severity:</span>
        {severityEntries.map(([sev, color]) => (
          <span key={sev} className="flex items-center gap-1 text-slate-400">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
            {sev}
          </span>
        ))}
      </div>
      <div className="flex items-center gap-3">
        <span className="text-slate-500">Asset type:</span>
        {typeEntries.slice(0, 6).map(([type, color]) => (
          <span key={type} className="flex items-center gap-1 text-slate-400">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
            {type}
          </span>
        ))}
      </div>
    </div>
  );
}
