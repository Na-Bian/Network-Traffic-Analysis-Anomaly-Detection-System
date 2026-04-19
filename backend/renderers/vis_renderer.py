import json
import math
import os
from collections import defaultdict


SMALL_GRAPH_NODES = 800
SMALL_GRAPH_EDGES = 2000
MEDIUM_GRAPH_NODES = 2000
MEDIUM_GRAPH_EDGES = 6000


def _edge_value(edge):
    return edge.get("value", 0) or 0


def _filter_top_k_edges(links, top_k_edges=0):
    if not top_k_edges or top_k_edges <= 0 or len(links) <= top_k_edges:
        return list(links)
    return sorted(links, key=_edge_value, reverse=True)[:top_k_edges]


def tr(_key, default):
    return default


def get_color_gradient(factor, start_hex="#E0F7FA", end_hex="#006064"):
    s_rgb = [int(start_hex[i:i + 2], 16) for i in (1, 3, 5)]
    e_rgb = [int(end_hex[i:i + 2], 16) for i in (1, 3, 5)]
    new_rgb = [int(s + (e - s) * factor) for s, e in zip(s_rgb, e_rgb)]
    return f"#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}"


def _graph_mode(node_count, edge_count):
    if node_count <= SMALL_GRAPH_NODES and edge_count <= SMALL_GRAPH_EDGES:
        return "interactive"
    if node_count <= MEDIUM_GRAPH_NODES and edge_count <= MEDIUM_GRAPH_EDGES:
        return "balanced"
    return "performance"


def _traffic_label(value):
    traffic_kb = value / 1024
    return f"{traffic_kb:.2f} KB" if traffic_kb < 1024 else f"{traffic_kb / 1024:.2f} MB"


def _position_nodes(nodes):
    grouped_nodes = defaultdict(list)
    for node in nodes:
        grouped_nodes[node.get("group", 1)].append(node)

    group_count = max(1, len(grouped_nodes))
    positioned = {}
    outer_radius = max(400, 260 * math.sqrt(group_count))

    for group_index, group in enumerate(sorted(grouped_nodes)):
        members = grouped_nodes[group]
        group_angle = 2 * math.pi * group_index / group_count
        group_x = outer_radius * math.cos(group_angle)
        group_y = outer_radius * math.sin(group_angle)
        member_radius = max(120, 26 * math.sqrt(len(members)))

        for member_index, node in enumerate(members):
            member_angle = 2 * math.pi * member_index / max(1, len(members))
            positioned[node["id"]] = {
                "x": group_x + member_radius * math.cos(member_angle),
                "y": group_y + member_radius * math.sin(member_angle),
            }
    return positioned


def _vis_options(mode, fontcolor):
    physics_enabled = mode != "performance"
    stabilization_iterations = 500 if mode == "interactive" else 150
    hide_edges_on_drag = mode != "interactive"

    return f"""
        var options = {{
          "nodes": {{
            "shape": "dot",
            "font": {{
              "color": "{fontcolor}",
              "size": 13
            }}
          }},
          "edges": {{
            "smooth": false,
            "arrows": {{
              "to": {{
                "enabled": true,
                "scaleFactor": 0.45
              }}
            }}
          }},
          "interaction": {{
            "hover": true,
            "tooltipDelay": 120,
            "hideEdgesOnDrag": {str(hide_edges_on_drag).lower()},
            "navigationButtons": true,
            "keyboard": true
          }},
          "physics": {{
            "enabled": {str(physics_enabled).lower()},
            "solver": "barnesHut",
            "barnesHut": {{
              "theta": 0.8,
              "gravitationalConstant": -18000,
              "centralGravity": 0.15,
              "springLength": 140,
              "springConstant": 0.03,
              "damping": 0.45,
              "avoidOverlap": 0.1
            }},
            "stabilization": {{
              "enabled": {str(physics_enabled).lower()},
              "iterations": {stabilization_iterations},
              "fit": true,
              "updateInterval": 50
            }},
            "minVelocity": 1.2
          }}
        }}
        """


def _load_graph(json_path):
    if not os.path.exists(json_path):
        raise FileNotFoundError(tr("subgraph_error_file_not_found", "错误：找不到文件 {}").format(json_path))

    with open(json_path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            raise ValueError(tr("subgraph_error_json_corrupted", "错误：JSON 格式损坏"))


def render_vis_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white",
                    data=None, mode=None, render_options=None):
    data = data if data is not None else _load_graph(json_path)
    nodes = data.get("nodes", [])
    render_options = render_options or {}
    links = _filter_top_k_edges(data.get("links", []), int(render_options.get("top_k_edges", 0) or 0))
    mode = mode or _graph_mode(len(nodes), len(links))
    performance_mode = mode == "performance"
    positioned_nodes = _position_nodes(nodes) if performance_mode else {}

    node_start_color = "#FFCCBC"
    node_end_color = "#E64A19"
    vis_nodes = []
    if nodes:
        groups = [node.get("group", 1) for node in nodes]
        min_g, max_g = min(groups), max(groups)
        g_range = max_g - min_g
        show_labels = mode == "interactive"

        for node in nodes:
            group = node.get("group", 1)
            factor = (group - min_g) / g_range if g_range > 0 else 0.5
            color = get_color_gradient(factor, node_start_color, node_end_color)
            label = node.get("label", "")
            position = positioned_nodes.get(node["id"], {})
            vis_node = {
                "id": node["id"],
                "label": label if show_labels else "",
                "color": color,
                "size": 9 if performance_mode else 15,
                "title": f"IP: {label} (Group: {group})",
                "physics": not performance_mode,
            }
            vis_node.update(position)
            vis_nodes.append(vis_node)

    group_colors = ["#FF4136", "#2ECC40", "#0074D9"]
    node_ids = {node["id"] for node in nodes}
    vis_edges = []
    if links:
        log_values = [math.log10(edge.get("value", 0) + 1) for edge in links]
        max_log, min_log = max(log_values), min(log_values)

        for edge in links:
            if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
                continue
            value = edge.get("value", 0)
            curr_log = math.log10(value + 1)
            factor = (curr_log - min_log) / (max_log - min_log) if max_log > min_log else 0
            groups = edge.get("groups", [])

            if groups:
                color = group_colors[groups[0] % len(group_colors)] if len(groups) == 1 else "#AAAAAA"
            else:
                color = get_color_gradient(factor, "#90A4AE", "#00E5FF")

            width = 1 + (factor * (4 if performance_mode else 10))
            vis_edges.append({
                "from": edge["source"],
                "to": edge["target"],
                "color": color,
                "width": width,
                "title": tr("edge_traffic_title", "流量: {}").format(_traffic_label(value)),
            })

    options_script = _vis_options(mode, fontcolor)
    nodes_json = json.dumps(vis_nodes, ensure_ascii=False)
    edges_json = json.dumps(vis_edges, ensure_ascii=False)
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/dist/vis-network.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js"></script>
  <style>
    html, body, #mynetwork {{
      width: 100%;
      height: 100%;
      margin: 0;
      padding: 0;
      background: {bgcolor};
      color: {fontcolor};
      overflow: hidden;
    }}
  </style>
</head>
<body>
  <div id="mynetwork"></div>
  <script>
    const nodes = new vis.DataSet({nodes_json});
    const edges = new vis.DataSet({edges_json});
    const data = {{ nodes, edges }};
    {options_script}
    const container = document.getElementById("mynetwork");
    const network = new vis.Network(container, data, options);
    window.network = network;
  </script>
</body>
</html>
"""

    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return {
        "renderer": "vis-network",
        "mode": mode,
        "nodes": len(nodes),
        "edges": len(vis_edges),
    }
