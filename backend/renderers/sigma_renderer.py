import json
import math
import os
import re
from collections import defaultdict

from .vis_renderer import (
    _filter_top_k_edges,
    _graph_mode,
    _load_graph,
    _position_nodes,
    _traffic_label,
    get_color_gradient,
)


DEFAULT_AGGREGATE_NODE_THRESHOLD = 10000
DEFAULT_AGGREGATE_EDGE_THRESHOLD = 30000
EXPAND_EDGE_LIMIT = 3500
IPV4_PATTERN = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _sigma_settings(bgcolor, fontcolor):
    return {
        "renderLabels": False,
        "renderEdgeLabels": False,
        "defaultNodeColor": "#9ca3af",
        "defaultEdgeColor": "#64748b",
        "labelColor": {"color": fontcolor},
        "labelFont": "Arial",
        "labelSize": 12,
        "hideEdgesOnMove": True,
        "hideLabelsOnMove": True,
        "allowInvalidContainer": True,
        "stagePadding": 24,
        "itemSizesReference": "positions",
        "backgroundColor": bgcolor,
    }


def _subnet24(label):
    match = IPV4_PATTERN.match(str(label))
    if not match:
        return str(label)
    octets = [int(part) for part in match.groups()]
    if any(octet > 255 for octet in octets):
        return str(label)
    return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"


def _build_sigma_nodes(nodes, mode):
    positioned_nodes = _position_nodes(nodes)
    groups = [node.get("group", 1) for node in nodes] or [1]
    min_g, max_g = min(groups), max(groups)
    g_range = max_g - min_g

    sigma_nodes = []
    for node in nodes:
        group = node.get("group", 1)
        factor = (group - min_g) / g_range if g_range > 0 else 0.5
        position = positioned_nodes.get(node["id"], {"x": 0, "y": 0})
        sigma_nodes.append({
            "key": str(node["id"]),
            "label": node.get("label", ""),
            "x": position["x"],
            "y": position["y"],
            "size": node.get("size", 3.5 if mode == "performance" else 5),
            "color": node.get("color", get_color_gradient(factor, "#FFCCBC", "#E64A19")),
            "subnet": node.get("subnet"),
            "memberCount": node.get("memberCount", 1),
            "aggregated": node.get("aggregated", False),
        })
    return sigma_nodes


def _build_sigma_edges(links, node_ids):
    edge_values = [math.log10(edge.get("value", 0) + 1) for edge in links]
    max_log = max(edge_values) if edge_values else 0
    min_log = min(edge_values) if edge_values else 0

    sigma_edges = []
    for index, edge in enumerate(links):
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            continue
        value = edge.get("value", 0)
        curr_log = math.log10(value + 1)
        factor = (curr_log - min_log) / (max_log - min_log) if max_log > min_log else 0
        sigma_edges.append({
            "key": f"e{index}",
            "source": str(edge["source"]),
            "target": str(edge["target"]),
            "size": edge.get("size", 0.6 + factor * 2.4),
            "color": edge.get("color", get_color_gradient(factor, "#90A4AE", "#00E5FF")),
            "label": _traffic_label(value),
            "value": value,
        })
    return sigma_edges


def _aggregate_by_subnet(nodes, links):
    subnet_members = defaultdict(list)
    node_to_subnet = {}
    for node in nodes:
        subnet = _subnet24(node.get("label", node["id"]))
        subnet_members[subnet].append(node)
        node_to_subnet[str(node["id"])] = subnet

    aggregate_nodes = []
    for index, subnet in enumerate(sorted(subnet_members)):
        members = subnet_members[subnet]
        member_count = len(members)
        aggregate_nodes.append({
            "id": subnet,
            "label": f"{subnet} ({member_count})",
            "group": index,
            "subnet": subnet,
            "memberCount": member_count,
            "aggregated": True,
            "size": max(5, min(28, 5 + math.log2(member_count + 1) * 3.2)),
        })

    edge_totals = defaultdict(float)
    for edge in links:
        source_subnet = node_to_subnet.get(str(edge.get("source")))
        target_subnet = node_to_subnet.get(str(edge.get("target")))
        if not source_subnet or not target_subnet or source_subnet == target_subnet:
            continue
        edge_totals[(source_subnet, target_subnet)] += edge.get("value", 0) or 0

    aggregate_links = [
        {"source": source, "target": target, "value": value}
        for (source, target), value in edge_totals.items()
    ]
    aggregate_links = _filter_top_k_edges(aggregate_links, 5000)
    return aggregate_nodes, aggregate_links, node_to_subnet


def render_sigma_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white",
                      data=None, mode=None, render_options=None, progress_callback=None):
    data = data if data is not None else _load_graph(json_path)
    nodes = data.get("nodes", [])
    render_options = render_options or {}
    if progress_callback:
        progress_callback("渲染进度: 正在筛选 Sigma 边数据...")
    links = _filter_top_k_edges(data.get("links", []), int(render_options.get("top_k_edges", 0) or 0))
    mode = mode or _graph_mode(len(nodes), len(links))

    aggregate_enabled = bool(render_options.get("aggregate_large_graph", False))
    aggregate_node_threshold = int(
        render_options.get("aggregate_node_threshold", DEFAULT_AGGREGATE_NODE_THRESHOLD)
    )
    aggregate_edge_threshold = int(
        render_options.get("aggregate_edge_threshold", DEFAULT_AGGREGATE_EDGE_THRESHOLD)
    )
    use_aggregate = aggregate_enabled and (
        len(nodes) >= aggregate_node_threshold or len(links) >= aggregate_edge_threshold
    )

    if progress_callback:
        progress_callback("渲染进度: 正在构建 Sigma 节点布局...")
    raw_nodes = _build_sigma_nodes(nodes, mode)
    node_ids = {node["id"] for node in nodes}
    raw_edges = _build_sigma_edges(links, node_ids)
    node_to_subnet = {}

    if use_aggregate:
        if progress_callback:
            progress_callback("渲染进度: 图规模较大，正在聚合子网视图...")
        aggregate_nodes, aggregate_links, node_to_subnet = _aggregate_by_subnet(nodes, links)
        sigma_nodes = _build_sigma_nodes(aggregate_nodes, "performance")
        sigma_edges = _build_sigma_edges(aggregate_links, {node["id"] for node in aggregate_nodes})
    else:
        sigma_nodes = raw_nodes
        sigma_edges = raw_edges

    if progress_callback:
        progress_callback("渲染进度: 正在序列化 Sigma HTML 内容...")
    settings_json = json.dumps(_sigma_settings(bgcolor, fontcolor), ensure_ascii=False)
    nodes_json = json.dumps(sigma_nodes, ensure_ascii=False)
    edges_json = json.dumps(sigma_edges, ensure_ascii=False)
    raw_nodes_json = json.dumps(raw_nodes if use_aggregate else [], ensure_ascii=False)
    raw_edges_json = json.dumps(raw_edges if use_aggregate else [], ensure_ascii=False)
    node_to_subnet_json = json.dumps(node_to_subnet, ensure_ascii=False)
    aggregate_json = json.dumps(use_aggregate)
    overview_text = (
        f"Sigma.js WebGL | {'subnets' if use_aggregate else 'nodes'}: {len(sigma_nodes)} "
        f"| edges: {len(sigma_edges)}"
    )
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/graphology/0.25.4/graphology.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/sigma.js/2.4.0/sigma.min.js"></script>
  <style>
    html, body, #sigma-container {{
      width: 100%;
      height: 100%;
      margin: 0;
      padding: 0;
      background: {bgcolor};
      color: {fontcolor};
      overflow: hidden;
      font-family: Arial, sans-serif;
    }}
    #info-panel {{
      position: fixed;
      left: 12px;
      bottom: 12px;
      max-width: 460px;
      padding: 8px 10px;
      background: rgba(0, 0, 0, 0.58);
      color: #fff;
      border-radius: 6px;
      font-size: 12px;
      pointer-events: none;
      z-index: 2;
    }}
    #reset-button {{
      display: none;
      position: fixed;
      top: 12px;
      left: 12px;
      padding: 7px 10px;
      border: 0;
      border-radius: 6px;
      background: rgba(15, 23, 42, 0.86);
      color: #fff;
      cursor: pointer;
      font-size: 12px;
      z-index: 3;
    }}
  </style>
</head>
<body>
  <div id="sigma-container"></div>
  <button id="reset-button">Back to subnet overview</button>
  <div id="info-panel">{overview_text}</div>
  <script>
    const graph = new graphology.Graph({{ multi: true, type: "directed" }});
    const nodes = {nodes_json};
    const edges = {edges_json};
    const rawNodes = {raw_nodes_json};
    const rawEdges = {raw_edges_json};
    const nodeToSubnet = {node_to_subnet_json};
    const aggregateEnabled = {aggregate_json};
    const overviewNodes = nodes;
    const overviewEdges = edges;
    const overviewText = "{overview_text}";
    let currentView = "overview";
    let hoveredNode = null;
    const infoPanel = document.getElementById("info-panel");
    const resetButton = document.getElementById("reset-button");

    function loadGraph(nextNodes, nextEdges) {{
      graph.clear();
      for (const node of nextNodes) {{
      graph.addNode(node.key, {{
        label: node.label,
        x: node.x,
        y: node.y,
        size: node.size,
        color: node.color,
        subnet: node.subnet || null,
        memberCount: node.memberCount || 1,
        aggregated: !!node.aggregated
      }});
      }}

      for (const edge of nextEdges) {{
        if (graph.hasNode(edge.source) && graph.hasNode(edge.target)) {{
          graph.addDirectedEdgeWithKey(edge.key, edge.source, edge.target, {{
            size: edge.size,
            color: edge.color,
            label: edge.label
          }});
        }}
      }}
    }}

    function expandSubnet(subnet) {{
      if (!aggregateEnabled || !subnet) return;
      const selected = new Set();
      for (const node of rawNodes) {{
        if (nodeToSubnet[node.key] === subnet) selected.add(node.key);
      }}
      const localEdges = [];
      for (const edge of rawEdges) {{
        if (selected.has(edge.source) || selected.has(edge.target)) {{
          selected.add(edge.source);
          selected.add(edge.target);
          localEdges.push(edge);
        }}
      }}
      localEdges.sort((a, b) => (b.value || 0) - (a.value || 0));
      const limitedEdges = localEdges.slice(0, {EXPAND_EDGE_LIMIT});
      const visible = new Set();
      for (const edge of limitedEdges) {{
        visible.add(edge.source);
        visible.add(edge.target);
      }}
      for (const node of selected) visible.add(node);
      const localNodes = rawNodes.filter(node => visible.has(node.key));
      loadGraph(localNodes, limitedEdges);
      currentView = "local";
      resetButton.style.display = "block";
      infoPanel.textContent = `Subnet: ${{subnet}} | local nodes: ${{localNodes.length}} | local edges: ${{limitedEdges.length}}`;
      renderer.getCamera().animatedReset();
    }}

    function resetOverview() {{
      loadGraph(overviewNodes, overviewEdges);
      hoveredNode = null;
      currentView = "overview";
      resetButton.style.display = "none";
      infoPanel.textContent = overviewText;
      renderer.getCamera().animatedReset();
    }}

    loadGraph(nodes, edges);
    const container = document.getElementById("sigma-container");
    const renderer = new Sigma(graph, container, {{
      ...{settings_json},
      nodeReducer: (node, data) => {{
        const result = {{ ...data }};
        if (hoveredNode && node !== hoveredNode && !graph.areNeighbors(node, hoveredNode)) {{
          result.color = "#475569";
          result.label = "";
        }}
        if (node === hoveredNode) {{
          result.highlighted = true;
          result.size = data.size * 1.7;
          result.label = data.label;
        }}
        return result;
      }},
      edgeReducer: (edge, data) => {{
        const result = {{ ...data }};
        if (hoveredNode) {{
          const extremities = graph.extremities(edge);
          if (!extremities.includes(hoveredNode)) {{
            result.hidden = true;
          }}
        }}
        return result;
      }}
    }});

    renderer.on("enterNode", (event) => {{
      hoveredNode = event.node;
      const attrs = graph.getNodeAttributes(event.node);
      const prefix = attrs.aggregated ? "Subnet" : "IP";
      const suffix = attrs.aggregated ? ` | hosts: ${{attrs.memberCount}} | click to expand` : "";
      infoPanel.textContent = `${{prefix}}: ${{attrs.label}} | neighbors: ${{graph.degree(event.node)}}${{suffix}}`;
      renderer.refresh({{ skipIndexation: true }});
    }});

    renderer.on("leaveNode", () => {{
      hoveredNode = null;
      if (currentView === "overview") {{
        infoPanel.textContent = overviewText;
      }}
      renderer.refresh({{ skipIndexation: true }});
    }});

    renderer.on("clickNode", (event) => {{
      const attrs = graph.getNodeAttributes(event.node);
      if (attrs.aggregated) {{
        expandSubnet(attrs.subnet);
      }}
    }});

    resetButton.addEventListener("click", resetOverview);

    window.sigmaRenderer = renderer;
    window.graph = graph;
  </script>
</body>
</html>
"""

    if progress_callback:
        progress_callback("渲染进度: 正在写入 Sigma HTML 文件...")
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html)

    if not os.path.exists(output_html_path):
        raise RuntimeError(f"错误：找不到文件 {output_html_path}")

    if progress_callback:
        progress_callback("渲染进度: Sigma HTML 已生成")
    return {
        "renderer": "sigma",
        "mode": mode,
        "nodes": len(sigma_nodes),
        "edges": len(sigma_edges),
    }
