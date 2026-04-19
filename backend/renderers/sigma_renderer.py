import json
import math
import os

from .vis_renderer import _graph_mode, _load_graph, _position_nodes, _traffic_label, get_color_gradient


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


def render_sigma_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white", data=None, mode=None):
    data = data if data is not None else _load_graph(json_path)
    nodes = data.get("nodes", [])
    links = data.get("links", [])
    mode = mode or _graph_mode(len(nodes), len(links))

    positioned_nodes = _position_nodes(nodes)
    groups = [node.get("group", 1) for node in nodes] or [1]
    min_g, max_g = min(groups), max(groups)
    g_range = max_g - min_g
    node_ids = {node["id"] for node in nodes}

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
            "size": 3.5 if mode == "performance" else 5,
            "color": get_color_gradient(factor, "#FFCCBC", "#E64A19"),
        })

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
            "size": 0.6 + factor * 2.4,
            "color": get_color_gradient(factor, "#90A4AE", "#00E5FF"),
            "label": _traffic_label(value),
        })

    settings_json = json.dumps(_sigma_settings(bgcolor, fontcolor), ensure_ascii=False)
    nodes_json = json.dumps(sigma_nodes, ensure_ascii=False)
    edges_json = json.dumps(sigma_edges, ensure_ascii=False)
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
  </style>
</head>
<body>
  <div id="sigma-container"></div>
  <div id="info-panel">Sigma.js WebGL | nodes: {len(sigma_nodes)} | edges: {len(sigma_edges)}</div>
  <script>
    const graph = new graphology.Graph({{ multi: true, type: "directed" }});
    const nodes = {nodes_json};
    const edges = {edges_json};

    for (const node of nodes) {{
      graph.addNode(node.key, {{
        label: node.label,
        x: node.x,
        y: node.y,
        size: node.size,
        color: node.color
      }});
    }}

    for (const edge of edges) {{
      if (graph.hasNode(edge.source) && graph.hasNode(edge.target)) {{
        graph.addDirectedEdgeWithKey(edge.key, edge.source, edge.target, {{
          size: edge.size,
          color: edge.color,
          label: edge.label
        }});
      }}
    }}

    let hoveredNode = null;
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
      document.getElementById("info-panel").textContent = `IP: ${{attrs.label}} | neighbors: ${{graph.degree(event.node)}}`;
      renderer.refresh({{ skipIndexation: true }});
    }});

    renderer.on("leaveNode", () => {{
      hoveredNode = null;
      document.getElementById("info-panel").textContent = "Sigma.js WebGL | nodes: {len(sigma_nodes)} | edges: {len(sigma_edges)}";
      renderer.refresh({{ skipIndexation: true }});
    }});

    window.sigmaRenderer = renderer;
    window.graph = graph;
  </script>
</body>
</html>
"""

    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html)

    if not os.path.exists(output_html_path):
        raise RuntimeError(f"错误：找不到文件 {output_html_path}")

    return {
        "renderer": "sigma",
        "mode": mode,
        "nodes": len(sigma_nodes),
        "edges": len(sigma_edges),
    }
