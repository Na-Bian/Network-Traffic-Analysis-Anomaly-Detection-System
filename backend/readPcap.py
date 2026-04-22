import argparse
import csv
import os
import socket
from dataclasses import dataclass
from typing import Callable

import dpkt

from gui.translator import tr


@dataclass
class FlowAggregate:
    data_size: int
    start_time: float
    end_time: float

    def update(self, timestamp: float, packet_size: int):
        self.data_size += packet_size
        if timestamp < self.start_time:
            self.start_time = timestamp
        if timestamp > self.end_time:
            self.end_time = timestamp


def _open_pcap_reader(file_obj):
    try:
        return dpkt.pcap.Reader(file_obj)
    except (ValueError, dpkt.dpkt.NeedData):
        file_obj.seek(0)
        return dpkt.pcapng.Reader(file_obj)


def _report_progress(
    callback: Callable[[str], None] | None,
    current_bytes: int,
    total_bytes: int,
    packet_count: int,
    flow_count: int,
):
    if callback is None or total_bytes <= 0:
        return
    percent = min(100, int(current_bytes * 100 / total_bytes))
    callback(
        tr(
            "pcap_progress",
            "PCAP 解析进度: {}%（已处理 {} 个数据包，聚合 {} 条流）",
        ).format(percent, packet_count, flow_count)
    )


def save_to_csv(pcap_input, csv_output, progress_callback: Callable[[str], None] | None = None):
    total_bytes = os.path.getsize(pcap_input)
    flow_map: dict[tuple[str, str, int, int, int], FlowAggregate] = {}
    packet_count = 0
    ipv4_packet_count = 0
    next_report_bytes = 0
    report_step = max(8 * 1024 * 1024, total_bytes // 100) if total_bytes > 0 else 8 * 1024 * 1024

    if progress_callback is not None:
        progress_callback(tr("parsing_pcap", "正在解析 PCAP 文件，请稍候..."))

    with open(pcap_input, "rb") as f:
        pcap = _open_pcap_reader(f)
        for timestamp, buffer in pcap:
            packet_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(buffer)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                packet = eth.data
                src = socket.inet_ntoa(packet.src)
                dst = socket.inet_ntoa(packet.dst)
                proto = int(packet.p)

                sport = 0
                dport = 0
                if isinstance(packet.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    sport = int(packet.data.sport)
                    dport = int(packet.data.dport)

                key = (src, dst, proto, sport, dport)
                packet_size = len(buffer)
                aggregate = flow_map.get(key)
                if aggregate is None:
                    flow_map[key] = FlowAggregate(packet_size, timestamp, timestamp)
                else:
                    aggregate.update(timestamp, packet_size)
                ipv4_packet_count += 1
            except Exception:
                continue

            current_pos = f.tell()
            if current_pos >= next_report_bytes:
                _report_progress(progress_callback, current_pos, total_bytes, packet_count, len(flow_map))
                next_report_bytes = current_pos + report_step

    if not flow_map:
        raise ValueError(tr("no_valid_ipv4_data", "PCAP 文件未提取到有效 IPv4 数据"))

    if progress_callback is not None:
        progress_callback(
            tr(
                "pcap_aggregation_done",
                "PCAP 解析完成：共处理 {} 个 IPv4 数据包，聚合得到 {} 条流，正在写出 CSV...",
            ).format(ipv4_packet_count, len(flow_map))
        )

    with open(csv_output, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Source", "Destination", "Protocol", "SrcPort", "DstPort", "DataSize", "Duration"])
        for (src, dst, proto, sport, dport), aggregate in flow_map.items():
            duration = aggregate.end_time - aggregate.start_time
            if duration <= 0:
                continue
            writer.writerow([src, dst, proto, sport, dport, aggregate.data_size, duration])

    if progress_callback is not None:
        progress_callback(tr("pcap_csv_written", "PCAP 转换完成: {}").format(csv_output))

    return csv_output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    save_to_csv(args.input, args.output, progress_callback=print)
