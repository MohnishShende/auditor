"""
Topology graph representation and node/edge correlation engine for Linux Server Audit.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TopologyNode:
    id: str
    label: str
    node_type: str  # "disk", "partition", "luks", "lvm_pv", "lvm_vg", "lvm_lv", "filesystem", "mount", "container", "app", "caddy_site", "interface", "port"
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type,
            "properties": self.properties,
        }


@dataclass
class TopologyEdge:
    source: str
    target: str
    relationship: str  # "contains", "encodes", "mapped_to", "mounted_on", "bound_to", "proxied_to", "runs_on"
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "properties": self.properties,
        }


class TopologyGraph:
    """Directed graph representing server component relationships."""

    def __init__(self) -> None:
        self.nodes: Dict[str, TopologyNode] = {}
        self.edges: List[TopologyEdge] = []

    def add_node(self, node_id: str, label: str, node_type: str, properties: Optional[Dict[str, Any]] = None) -> TopologyNode:
        if node_id not in self.nodes:
            self.nodes[node_id] = TopologyNode(
                id=node_id,
                label=label,
                node_type=node_type,
                properties=properties or {},
            )
        return self.nodes[node_id]

    def add_edge(self, source_id: str, target_id: str, relationship: str, properties: Optional[Dict[str, Any]] = None) -> None:
        self.edges.append(
            TopologyEdge(
                source=source_id,
                target=target_id,
                relationship=relationship,
                properties=properties or {},
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_mermaid(self) -> str:
        """Render topology graph as Mermaid flowchart."""
        lines = ["flowchart TD"]
        for node in self.nodes.values():
            safe_label = node.label.replace('"', "'")
            lines.append(f'    {node.id}["{safe_label}"]')
        for edge in self.edges:
            lines.append(f'    {edge.source} -->|"{edge.relationship}"| {edge.target}')
        return "\n".join(lines)
