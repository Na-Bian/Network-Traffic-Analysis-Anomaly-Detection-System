# gui/task_handler.py
import re

from PyQt6.QtCore import QObject, QTime
from PyQt6.QtWidgets import QTableWidgetItem

from .translator import tr, translate_backend_output, translate_violation_reason
from .worker import AnalyzerWorker


class TaskHandler(QObject):
    """负责所有后端任务的启动、输出处理和结果解析"""

    def __init__(self, main_window):
        super().__init__(main_window)
        self.main = main_window  # 持有主窗口引用，用于更新UI
        self.current_task_type = None
        self.task_output_buffer = []
        self.worker = None

    # ---------- 任务启动 ----------
    def run_worker(self, cmd, task_type, on_success=None):
        """启动AnalyzerWorker线程"""
        self.current_task_type = task_type
        self.main.log_text.clear()
        task_display_name = self.get_task_display_name(task_type)
        self.main.log_text.append(
            tr("task_start", "[{}] 🚀 开始执行任务: {}").format(
                QTime.currentTime().toString(), task_display_name
            )
        )
        self.main.log_text.append(
            tr("command_line", "[{}] 命令行: {}").format(
                QTime.currentTime().toString(), ' '.join(cmd)
            ) + "\n"
        )

        self.main.result_table.clear()
        self.main.result_table.setRowCount(0)
        self.main.result_table.setColumnCount(0)
        self.main.result_detail.clear()
        self.task_output_buffer.clear()

        self._show_output_view("log")

        self.worker = AnalyzerWorker(cmd)
        self.worker.output.connect(self.handle_worker_output)
        self.worker.error.connect(self.handle_worker_error)

        def success_handler():
            self.main.log_text.append(
                tr("task_complete", "\n[{}] ✅ 任务执行完成！正在解析结果...").format(
                    QTime.currentTime().toString()
                )
            )
            self.parse_task_results()
            if on_success:
                on_success()

        self.worker.success.connect(success_handler)
        self.worker.finished.connect(self.worker_cleanup)
        self.worker.start()

    def execute_command(self, base_cmd, task_type, generate_graph=False, graph_name=None):
        """构建完整命令并启动（简化版run_worker）"""
        full_cmd = base_cmd + [
            "--input", self.main.data_file,
            "--threads", str(self.main.thread_spin.value())
        ]
        json_path = html_path = None
        if generate_graph:
            if graph_name is None:
                graph_name = task_type
            json_path = self.main.temp_manager.get_path(f"{graph_name}.json")
            html_path = self.main.temp_manager.get_path(f"{graph_name}.html")
            full_cmd += ["--output-json", json_path]

        on_success = (lambda: self.main.generate_html(json_path, html_path)) if generate_graph else None
        self.run_worker(full_cmd, task_type=task_type, on_success=on_success)

    def worker_cleanup(self):
        self.worker = None

    # ---------- 输出处理 ----------
    def handle_worker_output(self, line):
        self.task_output_buffer.append(line)
        translated_line = translate_backend_output(line)
        self.main.log_text.append(translated_line)

    def handle_worker_error(self, line):
        self.task_output_buffer.append(line)
        translated_line = translate_backend_output(line)
        self.main.log_text.append(f"<span style='color:red;'>{translated_line}</span>")

    # ---------- 结果解析 ----------
    def parse_task_results(self):
        """根据任务类型分发到具体的解析方法"""
        if self.current_task_type == "custom-rule":
            self.parse_custom_rule_to_table()
        elif self.current_task_type == "flow-sort":
            self.parse_flow_sort_to_table()
        elif self.current_task_type in ["min-congestion", "min-hop", "min-risk"]:
            self.parse_path_to_detail()
        elif self.current_task_type == "compare-paths":
            self.parse_compare_paths_to_detail()
        elif self.current_task_type == "port-scan":
            self.parse_port_scan_to_table()
        elif self.current_task_type == "ddos-target":
            self.parse_ddos_to_table()
        elif self.current_task_type == "star-structures":
            self.parse_star_to_table()

        if self.main.result_table.rowCount() > 0:
            self._show_output_view("table")
        elif len(self.main.result_detail.toPlainText()) > 0:
            self._show_output_view("detail")

    def _show_output_view(self, route_key):
        """Switch to the requested output view across old and new result layouts."""
        pivot = getattr(self.main, "output_pivot", None)
        stack = getattr(self.main, "output_stack", None)

        if pivot is not None and stack is not None:
            widgets = {
                "log": self.main.log_text,
                "table": self.main.result_table,
                "detail": self.main.result_detail,
            }
            widget = widgets.get(route_key)
            if widget is not None:
                pivot.setCurrentItem(route_key)
                stack.setCurrentWidget(widget)

            results_interface = getattr(self.main, "results_interface", None)
            if results_interface is not None:
                self.main.switchTo(results_interface)
            return

        output_tabs = getattr(self.main, "output_tabs", None)
        if output_tabs is not None:
            index = {"log": 0, "table": 1, "detail": 2}.get(route_key, 0)
            output_tabs.setCurrentIndex(index)

    def parse_custom_rule_to_table(self):
        """将自定义规则检测结果填入表格"""
        headers = [
            tr("custom_rule_table_header_src_ip", "源IP"),
            tr("custom_rule_table_header_dst_ip", "目的IP"),
            tr("custom_rule_table_header_protocol", "协议类型"),
            tr("custom_rule_table_header_src_port", "源端口"),
            tr("custom_rule_table_header_dst_port", "目的端口"),
            tr("custom_rule_table_header_reason", "违规原因")
        ]
        self.main.result_table.setColumnCount(len(headers))
        self.main.result_table.setHorizontalHeaderLabels(headers)

        pattern = r"^\s*([\d\.]+) -> ([\d\.]+) \[proto=(\d+), srcPort=(\d+), dstPort=(\d+)\] reason: (.+)$"
        row_idx = 0
        for line in self.task_output_buffer:
            match = re.search(pattern, line)
            if match:
                src_ip, dst_ip, protocol, src_port, dst_port, reason = match.groups()
                localized_reason = translate_violation_reason(reason)
                self.main.result_table.insertRow(row_idx)
                self.main.result_table.setItem(row_idx, 0, QTableWidgetItem(src_ip))
                self.main.result_table.setItem(row_idx, 1, QTableWidgetItem(dst_ip))
                self.main.result_table.setItem(row_idx, 2, QTableWidgetItem(protocol))
                self.main.result_table.setItem(row_idx, 3, QTableWidgetItem(src_port))
                self.main.result_table.setItem(row_idx, 4, QTableWidgetItem(dst_port))
                self.main.result_table.setItem(row_idx, 5, QTableWidgetItem(localized_reason))
                row_idx += 1

    def parse_flow_sort_to_table(self):
        """根据后端输出的不同类型（总流量排序、HTTPS流量排序、出流量占比）动态设置表头和解析模式"""
        headers = None
        pattern = None
        for line in self.task_output_buffer:
            if line.startswith("节点总流量排序"):  # 后端固定输出，不翻译
                headers = [
                    tr("flow_sort_table_header_ip", "IP地址"),
                    tr("flow_sort_table_header_total_traffic", "总流量（字节）")
                ]
                pattern = r"^([\d\.]+),(\d+)$"
                break
            elif line.startswith("HTTPS节点流量排序"):  # 后端固定输出
                headers = [
                    tr("flow_sort_table_header_ip", "IP地址"),
                    tr("flow_sort_table_header_https_traffic", "HTTPS流量（字节）")
                ]
                pattern = r"^([\d\.]+),(\d+)$"
                break
            elif line.startswith("出流量占比 >") or line.startswith("出流量占比 >="):  # 后端固定输出
                headers = [
                    tr("flow_sort_table_header_ip", "IP地址"),
                    tr("flow_sort_table_header_total_traffic", "总流量（字节）"),
                    tr("flow_sort_table_header_out_ratio", "出流量占比")
                ]
                pattern = r"^([\d\.]+),(\d+),([\d\.]+)$"
                break
        if not headers:
            return

        self.main.result_table.setColumnCount(len(headers))
        self.main.result_table.setHorizontalHeaderLabels(headers)

        row_idx = 0
        for line in self.task_output_buffer:
            match = re.search(pattern, line)
            if match:
                self.main.result_table.insertRow(row_idx)
                for col, val in enumerate(match.groups()):
                    self.main.result_table.setItem(row_idx, col, QTableWidgetItem(val))
                row_idx += 1

    def parse_port_scan_to_table(self):
        headers = [
            tr("port_scan_table_header_ip", "IP地址"),
            tr("port_scan_table_header_port_count", "最大目的端口数"),
            tr("port_scan_table_header_target_count", "最大目标数"),
            tr("port_scan_table_header_scan_type", "扫描类型"),
            tr("flow_sort_table_header_out_ratio", "出流量占比"),
            tr("flow_sort_table_header_total_traffic", "总流量（字节）")
        ]
        self.main.result_table.setColumnCount(len(headers))
        self.main.result_table.setHorizontalHeaderLabels(headers)

        row_idx = 0
        for line in self.task_output_buffer:
            # 匹配格式：IP,最大端口数,最大目标数,扫描类型,出流量占比,总流量
            match = re.match(r'^([\d\.]+),(\d+),(\d+),([a-z]+),([\d\.]+),(\d+)$', line.strip())
            if match:
                ip, port_count, target_count, scan_type, ratio, total_traffic = match.groups()
                scan_type = {
                    "vertical": tr("port_scan_type_vertical", "纵向扫描"),
                    "horizontal": tr("port_scan_type_horizontal", "横向扫描"),
                    "mixed": tr("port_scan_type_mixed", "混合扫描")
                }.get(scan_type, scan_type)
                self.main.result_table.insertRow(row_idx)
                self.main.result_table.setItem(row_idx, 0, QTableWidgetItem(ip))
                self.main.result_table.setItem(row_idx, 1, QTableWidgetItem(port_count))
                self.main.result_table.setItem(row_idx, 2, QTableWidgetItem(target_count))
                self.main.result_table.setItem(row_idx, 3, QTableWidgetItem(scan_type))
                self.main.result_table.setItem(row_idx, 4, QTableWidgetItem(ratio))
                self.main.result_table.setItem(row_idx, 5, QTableWidgetItem(total_traffic))
                row_idx += 1

    def parse_ddos_to_table(self):
        """DDoS目标检测结果解析"""
        headers = [
            tr("ddos_table_header_ip", "IP地址"),
            tr("ddos_table_header_neighbor_count", "入方向源数"),
            tr("ddos_table_header_in_data", "入流量（字节）"),
            tr("ddos_table_header_in_ratio", "入流量占比")
        ]
        self.main.result_table.setColumnCount(len(headers))
        self.main.result_table.setHorizontalHeaderLabels(headers)

        row_idx = 0
        for line in self.task_output_buffer:
            # 匹配格式：IP,入方向源数,入流量,入流量占比
            match = re.match(r'^([\d\.]+),(\d+),(\d+),([\d\.]+)$', line.strip())
            if match:
                ip, neighbor_count, in_data, in_ratio = match.groups()
                self.main.result_table.insertRow(row_idx)
                self.main.result_table.setItem(row_idx, 0, QTableWidgetItem(ip))
                self.main.result_table.setItem(row_idx, 1, QTableWidgetItem(neighbor_count))
                self.main.result_table.setItem(row_idx, 2, QTableWidgetItem(in_data))
                self.main.result_table.setItem(row_idx, 3, QTableWidgetItem(in_ratio))
                row_idx += 1

    def parse_star_to_table(self):
        """星型结构结果解析"""
        headers = [
            tr("star_table_header_center_ip", "中心IP"),
            tr("star_table_header_neighbor_count", "邻居叶子数"),
            tr("star_table_header_total_traffic", "总流量"),
            tr("ddos_table_header_in_data", "入流量（字节）"),
            tr("star_table_header_out_data", "出流量（字节）"),
            tr("star_table_header_leaf_ratio", "叶子占比")
        ]
        self.main.result_table.setColumnCount(len(headers))
        self.main.result_table.setHorizontalHeaderLabels(headers)

        # 正则中的“星型”等是后端固定输出，不翻译
        pattern = r"星型 \d+: 中心=([\d\.]+), 邻居数=(\d+), 总流量=(\d+), 入流量=(\d+), 出流量=(\d+), 叶子占比=([\d\.]+)"
        row_idx = 0
        for line in self.task_output_buffer:
            match = re.search(pattern, line)
            if match:
                center_ip, neighbor_count, total, in_data, out_data, leaf_ratio = match.groups()
                self.main.result_table.insertRow(row_idx)
                self.main.result_table.setItem(row_idx, 0, QTableWidgetItem(center_ip))
                self.main.result_table.setItem(row_idx, 1, QTableWidgetItem(neighbor_count))
                self.main.result_table.setItem(row_idx, 2, QTableWidgetItem(total))
                self.main.result_table.setItem(row_idx, 3, QTableWidgetItem(in_data))
                self.main.result_table.setItem(row_idx, 4, QTableWidgetItem(out_data))
                self.main.result_table.setItem(row_idx, 5, QTableWidgetItem(leaf_ratio))
                row_idx += 1

    def parse_path_to_detail(self):
        """单一路径解析（min-congestion / min-hop / min-risk）"""
        task_type = self.current_task_type
        # 确定度量值显示标签
        metric_label = {
            "min-congestion": tr("path_detail_congestion_label", "拥塞值: {}"),
            "min-hop": tr("path_detail_hop_label", "跳数: {}"),
            "min-risk": tr("path_detail_risk_label", "风险值: {}")
        }.get(task_type, tr("path_detail_congestion_label", "拥塞值: {}"))

        html = f"<h3 style='color: #2c3e50;'>{tr('path_detail_title', '🔎 路径分析结果')}</h3>"

        # 统计路径行并提取标题中的额外信息
        path_lines = []
        extra_info = {}  # 用于存放最小跳数/最小风险值
        for line in self.task_output_buffer:
            line = line.strip()
            if not line:
                continue
            # 识别标题行
            if "最小拥塞路径" in line:
                m = re.search(r"共 (\d+) 条", line)
                if m:
                    extra_info["count"] = m.group(1)
            elif "最小跳数路径" in line:
                m = re.search(r"最小跳数 = (\d+)", line)
                if m:
                    extra_info["min_hop"] = m.group(1)
            elif "最小风险路径" in line:
                m = re.search(r"最小风险值 = ([\d.]+)", line)
                if m:
                    extra_info["min_risk"] = m.group(1)
            # 收集路径行（包含IP和|符号）
            if "|" in line and re.search(r'\d+\.\d+\.\d+\.\d+', line):
                path_lines.append(line)

        # 构建统计信息
        if task_type == "min-congestion":
            if "count" in extra_info:
                html += f"<p><strong>{tr('path_found_count_congestion', '共找到 {} 条最小拥塞路径：').format(extra_info['count'])}</strong></p>"
        elif task_type == "min-hop":
            if "min_hop" in extra_info:
                html += f"<p><strong>{tr('path_found_count_hop', '最小跳数为 {}，共找到 {} 条路径：').format(extra_info['min_hop'], len(path_lines))}</strong></p>"
        elif task_type == "min-risk":
            if "min_risk" in extra_info:
                html += f"<p><strong>{tr('path_found_count_risk', '最小风险值为 {}，共找到 {} 条路径：').format(extra_info['min_risk'], len(path_lines))}</strong></p>"

        # 解析每条路径
        if path_lines:
            for line in path_lines:
                parts = line.split('|')
                ip_part = parts[0].strip()
                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', ip_part)
                if ips:
                    formatted = " → ".join(ips)
                    metric_pattern = r'risk=([\d.]+)' if task_type == "min-risk" else r'congestion=([\d.]+)'
                    metric_match = re.search(metric_pattern, line)
                    if metric_match:
                        metric_val = metric_match.group(1)
                        formatted += f" <span style='color:#7f8c8d;'>({metric_label.format(metric_val)})</span>"
                    html += f"<p style='font-family:monospace;'>{formatted}</p>"
        else:
            html += "<p style='color: red;'>" + tr("path_detail_not_found", "未找到符合条件的路径。") + "</p>"

        self.main.result_detail.setHtml(html)

    def parse_compare_paths_to_detail(self):
        """路径对比结果解析"""
        html = "<h3 style='color: #2c3e50; margin-bottom:15px;'>" + tr("compare_paths_detail_title",
                                                                       "🔎 路径对比结果") + "</h3>"

        # 策略名称映射（用于显示翻译）
        strategy_names = {
            "最小拥塞": tr("compare_paths_strategy_min_congestion", "最小拥塞"),
            "最小跳数": tr("compare_paths_strategy_min_hop", "最小跳数"),
            "最小风险": tr("compare_paths_strategy_min_risk", "最小风险")
        }
        colors = {"最小拥塞": "#e74c3c", "最小跳数": "#3498db", "最小风险": "#2ecc71"}

        stats = {
            "最小拥塞": {"count": 0, "values": [], "metric": None},
            "最小跳数": {"count": 0, "values": [], "metric": None},
            "最小风险": {"count": 0, "values": [], "metric": None}
        }

        current_section = None
        path_found = False
        path_lines = []

        for line in self.task_output_buffer:
            line = line.strip()
            if not line:
                continue

            # 匹配 C++ 输出的标题
            if "最小拥塞路径" in line:
                current_section = "最小拥塞"
                continue
            elif "最小跳数路径" in line:
                current_section = "最小跳数"
                # 提取最小跳数值
                m = re.search(r"最小跳数 = (\d+)", line)
                if m:
                    stats["最小跳数"]["metric"] = m.group(1)
                continue
            elif "最小风险路径" in line:
                current_section = "最小风险"
                m = re.search(r"最小风险值 = ([\d.]+)", line)
                if m:
                    stats["最小风险"]["metric"] = m.group(1)
                continue

            if current_section and "|" in line and re.search(r'\d+\.\d+\.\d+\.\d+', line):
                path_found = True
                stats[current_section]["count"] += 1
                metric_pattern = r'risk=([\d.]+)' if current_section == "最小风险" else r'congestion=([\d.]+)'
                metric_match = re.search(metric_pattern, line)
                if metric_match:
                    val = float(metric_match.group(1))
                    stats[current_section]["values"].append(val)
                path_lines.append((current_section, line))

        if not path_found:
            html += "<p style='color: red;'>" + tr("compare_paths_not_found", "未找到符合条件的路径。") + "</p>"
            self.main.result_detail.setHtml(html)
            return

        # 表格表头
        html += "<table style='width:100%; border-collapse:collapse; margin-bottom:20px; background:#f8f9fa;'>"
        html += "<tr><th style='padding:8px; border:1px solid #ddd; text-align:left;'>" + \
                tr("compare_paths_table_header_strategy", "策略") + "</th>"
        html += "<th style='padding:8px; border:1px solid #ddd; text-align:center;'>" + \
                tr("compare_paths_table_header_count", "路径数量") + "</th>"
        html += "<th style='padding:8px; border:1px solid #ddd; text-align:center;'>" + \
                tr("compare_paths_table_header_metric_range", "指标范围(Min ~ Max)") + "</th></tr>"

        for strategy, data in stats.items():
            color = colors[strategy]
            display_name = strategy_names[strategy]
            vals = data["values"]
            if not vals:
                cong_display = "N/A"
            else:
                min_v, max_v = min(vals), max(vals)
                if min_v == max_v:
                    cong_display = f"{min_v:.1f}"
                else:
                    cong_display = f"{min_v:.1f} ~ {max_v:.1f}"

            html += f"<tr>"
            html += f"<td style='padding:8px; border:1px solid #ddd; color:{color};'><b>{display_name}</b></td>"
            html += f"<td style='padding:8px; border:1px solid #ddd; text-align:center;'>{data['count']}</td>"
            html += f"<td style='padding:8px; border:1px solid #ddd; text-align:center;'>{cong_display}</td>"
            html += "</tr>"
        html += "</table>"

        # 路径详细列表
        current_section = None
        for strategy, line in path_lines:
            if current_section != strategy:
                if current_section:
                    html += "</div>"
                current_section = strategy
                html += f"<div style='margin-top:15px;'>"
                html += f"<h4 style='color:{colors[strategy]}; border-left:5px solid {colors[strategy]}; padding-left:10px;'>{strategy_names[strategy]}</h4>"

                # 显示当前策略的度量值
                if strategy == "最小跳数" and stats[strategy]["metric"] is not None:
                    html += f"<p style='margin-left:10px; color:#7f8c8d; font-size:0.9em;'>{tr('compare_paths_min_hop_display', '最小跳数: {}').format(stats[strategy]['metric'])}</p>"
                elif strategy == "最小风险" and stats[strategy]["metric"] is not None:
                    html += f"<p style='margin-left:10px; color:#7f8c8d; font-size:0.9em;'>{tr('compare_paths_min_risk_display', '最小风险值: {}').format(stats[strategy]['metric'])}</p>"

            parts = line.split('|')
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', parts[0])
            if ips:
                formatted = " → ".join(ips)
                metric_pattern = r'risk=([\d.]+)' if strategy == "最小风险" else r'congestion=([\d.]+)'
                metric_match = re.search(metric_pattern, line)
                if metric_match:
                    label_key = "compare_paths_risk_label" if strategy == "最小风险" else "compare_paths_congestion_label"
                    label_fallback = "风险值: {}" if strategy == "最小风险" else "拥塞值: {}"
                    formatted += f" <span style='color:#7f8c8d;'>({tr(label_key, label_fallback).format(metric_match.group(1))})</span>"
                html += f"<p style='margin-left:20px; font-family:monospace;'>{formatted}</p>"

        if current_section:
            html += "</div>"
        self.main.result_detail.setHtml(html)

    # ---------- 辅助 ----------
    def get_task_display_name(self, task_type):
        task_names = {
            "full-graph": tr("task_full_graph", "全网拓扑"),
            "subgraph": tr("task_subgraph", "子图"),
            "flow-sort": tr("task_flow_sort", "流量排序"),
            "min-congestion": tr("task_min_congestion", "最小拥塞路径"),
            "min-hop": tr("task_min_hop", "最小跳数路径"),
            "min-risk": tr("task_min_risk", "最小风险路径"),
            "compare-paths": tr("task_compare_paths", "路径对比"),
            "port-scan": tr("task_port_scan", "端口扫描检测"),
            "ddos-target": tr("task_ddos_target", "DDoS目标检测"),
            "star-structures": tr("task_star_structures", "星型结构查找"),
            "custom-rule": tr("task_custom_rule", "自定义规则检测"),
        }
        return task_names.get(task_type, task_type)
