# subgraph.py
import argparse
import json
import math
import os

from pyvis.network import Network

from gui.translator import tr


def get_color_gradient(factor, start_hex="#E0F7FA", end_hex="#006064"):
    s_rgb = [int(start_hex[i:i + 2], 16) for i in (1, 3, 5)]
    e_rgb = [int(end_hex[i:i + 2], 16) for i in (1, 3, 5)]
    new_rgb = [int(s + (e - s) * factor) for s, e in zip(s_rgb, e_rgb)]
    return f"#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}"


def generate_html(json_path, output_html_path, bgcolor="#222222", fontcolor="white"):
    if not os.path.exists(json_path):
        print(tr("subgraph_error_file_not_found", "错误：找不到文件 {}").format(json_path))
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(tr("subgraph_error_json_corrupted", "错误：JSON 格式损坏"))
            return

    net = Network(height="900px", width="1600px", bgcolor=bgcolor, font_color=fontcolor, directed=True)

    # 节点颜色范围设定
    node_start_color = "#FFCCBC"
    node_end_color = "#E64A19"

    # 添加节点
    nodes = data.get("nodes", [])
    if nodes:
        groups = [node['group'] for node in nodes]
        min_g, max_g = min(groups), max(groups)
        g_range = max_g - min_g
        for node in nodes:
            factor = (node['group'] - min_g) / g_range if g_range > 0 else 0.5
            color = get_color_gradient(factor, node_start_color, node_end_color)
            net.add_node(node['id'], label=node['label'], color=color, size=15,
                         title=f"IP: {node['label']} (Group: {node['group']})")

    # 路径对比模块，定义每组对应的颜色
    group_colors = ["#FF4136", "#2ECC40", "#0074D9"]  # 红、绿、蓝

    # 添加边
    links = data.get("links", [])
    if links:
        # 计算流量对 value 的归一化
        log_values = [math.log10(edge['value'] + 1) for edge in links]
        max_log, min_log = max(log_values), min(log_values)

        for edge in links:
            curr_log = math.log10(edge['value'] + 1)
            factor = (curr_log - min_log) / (max_log - min_log) if max_log > min_log else 0

            # 根据 groups 字段决定颜色
            groups = edge.get('groups', [])
            if groups:
                if len(groups) == 1:
                    # 只属于一个组：使用该组的颜色
                    color = group_colors[groups[0] % len(group_colors)]
                else:
                    # 属于多个组：使用混合色
                    color = "#AAAAAA"
            else:
                # 无groups字段，基于流量的颜色渐变
                color = get_color_gradient(factor, "#90A4AE", "#00E5FF")

            width = 1 + (factor * 10)  # 宽度由流量决定

            # 流量单位转换
            traffic_kb = edge['value'] / 1024
            label_text = f"{traffic_kb:.2f} KB" if traffic_kb < 1024 else f"{traffic_kb / 1024:.2f} MB"

            net.add_edge(edge['source'], edge['target'], color=color, width=width,
                         title=tr("edge_traffic_title", "流量: {}").format(label_text))

    # 禁用物理引擎
    net.toggle_physics(True)
    net.set_options("""
        var options = {
          "physics": {
            "barnesHut": { "gravitationalConstant": -2000, "centralGravity": 0.3, "springLength": 150 },
            "minVelocity": 0.75
          }
        }
        """)

    net.save_graph(output_html_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bgcolor", default="#222222", help="背景颜色，例如 #222222")
    parser.add_argument("--fontcolor", default="white", help="文字颜色，例如 white")
    args = parser.parse_args()
    generate_html(args.json, args.output, args.bgcolor, args.fontcolor)
