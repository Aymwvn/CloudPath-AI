import dagre from '@dagrejs/dagre';
import type { Node, Edge } from '@xyflow/react';
import type { GraphNode, GraphEdge } from './api';

const NODE_WIDTH = 180;
const NODE_HEIGHT = 56;

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#64748b',
};

const TYPE_COLORS: Record<string, string> = {
  INTERNET: '#dc2626',
  EC2: '#0ea5e9',
  S3: '#22c55e',
  RDS: '#a855f7',
  ROLE: '#f59e0b',
  USER: '#f59e0b',
  SECURITY_GROUP: '#64748b',
  SECRET: '#ec4899',
  KMS_KEY: '#ec4899',
  LAMBDA: '#f97316',
};

/**
 * Lays out the graph left-to-right (matches how these attack paths
 * actually read: Internet -> ... -> sensitive target) using dagre's
 * layered/hierarchical algorithm — a plain force-directed layout would
 * look messy for what's fundamentally a DAG-shaped structure.
 */
export function layoutGraph(
  nodes: GraphNode[],
  edges: GraphEdge[]
): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', nodesep: 40, ranksep: 120 });

  for (const node of nodes) {
    g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }
  for (const edge of edges) {
    // dagre needs both endpoints registered as nodes — skip any edge
    // pointing at a node that wasn't in the node list (shouldn't happen
    // given how the backend builds this payload, but defensive here).
    if (g.hasNode(edge.source) && g.hasNode(edge.target)) {
      g.setEdge(edge.source, edge.target);
    }
  }

  dagre.layout(g);

  const positionedNodes: Node[] = nodes.map((node) => {
    const pos = g.node(node.id);
    const borderColor = node.on_attack_path
      ? SEVERITY_COLORS[node.max_severity ?? 'LOW']
      : TYPE_COLORS[node.type] ?? '#475569';

    return {
      id: node.id,
      position: { x: pos?.x ?? 0, y: pos?.y ?? 0 },
      data: { label: `${node.type}\n${node.label}` },
      style: {
        width: NODE_WIDTH,
        border: `2px solid ${borderColor}`,
        borderRadius: 8,
        background: '#0f172a',
        color: '#e2e8f0',
        fontSize: 11,
        padding: 8,
        whiteSpace: 'pre-line' as const,
        textAlign: 'center' as const,
        boxShadow: node.on_attack_path ? `0 0 12px ${borderColor}66` : undefined,
      },
    };
  });

  const positionedEdges: Edge[] = edges.map((edge) => {
    const color = edge.on_attack_path ? SEVERITY_COLORS[edge.max_severity ?? 'LOW'] : '#334155';
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.type,
      animated: edge.on_attack_path,
      style: { stroke: color, strokeWidth: edge.on_attack_path ? 2.5 : 1 },
      labelStyle: { fill: '#94a3b8', fontSize: 9 },
      markerEnd: { type: 'arrowclosed' as const, color },
      // carries the full GraphEdge (including evidence) so the click
      // handler in AttackGraph.tsx can show relationship detail without
      // a second lookup — React Flow's `data` field is exactly meant
      // for attaching arbitrary payload like this to an edge.
      data: { graphEdge: edge },
    };
  });

  return { nodes: positionedNodes, edges: positionedEdges };
}

export { SEVERITY_COLORS, TYPE_COLORS };
