import re

from .manager import tr


def translate_violation_reason(reason):
    """
    Translate a backend violation reason into the current UI language.
    Multiple clauses separated by semicolons are translated independently.
    """
    if not reason:
        return ""

    clause_patterns = [
        (r"通信匹配拒绝规则", "violation_deny_match"),
        (r"对端IP([\d.]+)不在允许范围内", "violation_allow_ip_range"),
        (r"违反IP地址范围规则", "violation_ip_range"),
        (r"协议类型(\d+)违反规则", "violation_protocol"),
        (r"源端口(\d+)违反规则", "violation_src_port"),
        (r"目的端口(\d+)违反规则", "violation_dst_port"),
        (r"协议类型(\d+)不在允许规则内", "violation_protocol_not_allowed"),
        (r"源端口(\d+)不在允许规则内", "violation_src_port_not_allowed"),
        (r"目的端口(\d+)不在允许规则内", "violation_dst_port_not_allowed"),
        (
            r"与([\d.]+)的通信流量为(\d+) bytes，超过了最大流量阈值(\d+) bytes",
            "violation_traffic",
        ),
    ]

    translated_clauses = []
    for clause in [c.strip() for c in reason.split(";") if c.strip()]:
        for pattern, key in clause_patterns:
            match = re.search(pattern, clause)
            if match:
                translated_clauses.append(tr(key, key).format(*match.groups()))
                break
        else:
            translated_clauses.append(clause)

    return "；".join(translated_clauses)


def translate_backend_output(line):
    """Translate human-readable Chinese backend output as a compatibility layer."""
    patterns = [
        (r"开始加载数据集\.\.\.", "backend_dataset_load_start"),
        (r"数据集已加载完成", "backend_dataset_load_done"),
        (r"进度: 开始解析 CSV 文件\.\.\.", "backend_csv_parse_start"),
        (r"进度: CSV 解析完成，保留 (\d+) 条有效记录，识别 (\d+) 个唯一节点", "backend_csv_parse_done"),
        (r"进度: 使用 (\d+) 个线程并行构建局部图\.\.\.", "backend_graph_build_parallel"),
        (r"进度: 图模型构建完成", "backend_graph_build_done"),
        (r"开始预热图索引与邻居缓存\.\.\.", "backend_index_warmup_start"),
        (r"正在构建邻居缓存\.\.\.", "backend_neighbor_cache_building"),
        (r"进度: 邻居分析开始，节点数=(\d+)，线程数=(\d+)", "backend_neighbor_analysis_start"),
        (r"进度: 邻居分析第一阶段完成（出边聚合）", "backend_neighbor_analysis_out_done"),
        (r"进度: 邻居分析第二阶段完成（入边聚合）", "backend_neighbor_analysis_in_done"),
        (r"索引预热完成", "backend_index_warmup_done"),
        (r"进度: 端口扫描检测复用会话缓存结果\.\.\.", "backend_port_scan_cache_reused"),
        (r"进度: DDoS 目标检测复用会话缓存结果\.\.\.", "backend_ddos_cache_reused"),
        (r"进度: 星型结构检测复用会话缓存结果\.\.\.", "backend_star_cache_reused"),
        (r"复用已缓存的端口扫描检测结果", "backend_port_scan_result_reused"),
        (r"复用已缓存的 DDoS 检测结果", "backend_ddos_result_reused"),
        (r"复用已缓存的星型结构检测结果", "backend_star_result_reused"),
        (r"开始执行任务: (.*)", "backend_task_start"),
        (r"进度: 正在导出全网拓扑 JSON\.\.\.", "backend_full_graph_exporting"),
        (r"PCAP 解析进度: (\d+)%（已处理 (\d+) 个数据包，聚合 (\d+) 条流）", "pcap_progress"),
        (r"PCAP 解析完成：共处理 (\d+) 个 IPv4 数据包，聚合得到 (\d+) 条流，正在写出 CSV\.\.\.", "pcap_aggregation_done"),
        (r"PCAP 转换完成: (.*)", "pcap_csv_written"),
        (r"渲染进度: 准备读取图数据\.\.\.", "render_prepare_graph_data"),
        (r"渲染进度: 图数据已就绪，节点 (\d+) 个，边 (\d+) 条", "render_graph_ready"),
        (r"渲染进度: 选择 (.+) 渲染器，模式=(.+)", "render_choose_renderer"),
        (r"渲染进度: 正在筛选可视化边\.\.\.", "render_filter_vis_edges"),
        (r"渲染进度: 正在准备节点布局\.\.\.", "render_prepare_node_layout"),
        (r"渲染进度: 正在构建节点与边的数据集\.\.\.", "render_build_dataset"),
        (r"渲染进度: 正在序列化 HTML 内容\.\.\.", "render_serialize_html"),
        (r"渲染进度: 正在写入 HTML 文件\.\.\.", "render_write_html"),
        (r"渲染进度: vis-network HTML 已生成", "render_vis_html_ready"),
        (r"渲染进度: 正在筛选 Sigma 边数据\.\.\.", "render_filter_sigma_edges"),
        (r"渲染进度: 正在构建 Sigma 节点布局\.\.\.", "render_build_sigma_layout"),
        (r"渲染进度: 图规模较大，正在聚合子网视图\.\.\.", "render_aggregate_subnets"),
        (r"渲染进度: 正在序列化 Sigma HTML 内容\.\.\.", "render_serialize_sigma_html"),
        (r"渲染进度: 正在写入 Sigma HTML 文件\.\.\.", "render_write_sigma_html"),
        (r"渲染进度: Sigma HTML 已生成", "render_sigma_html_ready"),
        (r"Full graph exported to (.*)", "full_graph_exported"),
        (r"Rendering graph, please wait\.\.\.", "generate_html_rendering"),
        (r"Subgraph loaded\.\.\.", "display_html_success"),
        (r"Graph rendering completed!", "generate_html_success"),
        (r"全网拓扑已导出到 (.*)", "full_graph_exported"),
        (r"子图已导出到 (.*)", "subgraph_exported"),
        (r"检测到端口扫描攻击者 (\d+) 个:", "port_scan_detected"),
        (r"检测到DDoS攻击目标 (\d+) 个:", "ddos_target_detected"),
        (r"找到星型结构 (\d+) 个:", "star_structure_found"),
        (r"违反规则的通信记录 (\d+) 条:", "custom_rule_violations"),
        (r"路径子图已导出到 (.*)", "path_subgraph_exported"),
        (r"对比路径子图已导出到 (.*)", "compare_paths_subgraph_exported"),
        (r"端口扫描攻击者子图已导出到 (.*)", "port_scan_subgraph_exported"),
        (r"DDoS攻击目标子图已导出到 (.*)", "ddos_subgraph_exported"),
        (r"星型结构子图已导出到 (.*)", "star_subgraph_exported"),
        (r"违规通信子图已导出到 (.*)", "custom_rule_subgraph_exported"),
        (r"没有找到从 (.*) 到 (.*) 的路径", "no_path_found"),
        (r"最小拥塞路径 \(共 (\d+) 条\):", "min_congestion_paths"),
        (r"最小跳数路径 \(最小跳数 = (\d+)\):", "min_hop_paths"),
        (r"最小风险路径 \(最小风险值 = ([\d.]+)\):", "min_risk_paths"),
        (r"【最小拥塞路径】", "min_congestion_section"),
        (r"【最小跳数路径】", "min_hop_section"),
        (r"【最小风险路径】", "min_risk_section"),
        (r"  无违规记录", "no_violations"),
        (r"错误: (.*)", "error_prefix"),
        (r"警告: (.*)", "warning_prefix"),
    ]

    for pattern, key in patterns:
        match = re.search(pattern, line)
        if not match:
            continue

        translated = tr(key, key)
        try:
            return translated.format(*match.groups())
        except IndexError:
            return line

    return line
