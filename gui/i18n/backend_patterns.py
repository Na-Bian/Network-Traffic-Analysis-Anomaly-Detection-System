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
