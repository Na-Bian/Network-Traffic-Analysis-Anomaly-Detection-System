# readPcap.py
import argparse
import socket

import dpkt
import pandas as pd

from gui.translator import tr


def pcap_to_df(pcap_path="my.pcap"):
    data = []
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)  # 将pcap文件解析为可迭代对象
        for timestamp, buffer in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buffer)  # 解析以太网帧
                if not isinstance(eth.data, dpkt.ip.IP):  # 只处理IPv4数据包
                    continue

                # 解析IP数据包
                packet = eth.data
                src = socket.inet_ntoa(packet.src)
                dst = socket.inet_ntoa(packet.dst)
                proto = packet.p

                sport = None
                dport = None
                # 解析TCP/UDP/ICMP数据包的源端口和目的端口
                if isinstance(packet.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):  # 处理TCP和UDP数据包
                    sport = packet.data.sport
                    dport = packet.data.dport

                data.append([timestamp, src, dst, proto, sport, dport, len(buffer)])
            except:
                continue

    return pd.DataFrame(data,
                        columns=['Timestamp', 'Source', 'Destination', 'Protocol', 'SrcPort', 'DstPort', 'Length'])


# 将PCAP文件转换为CSV文件，输出到指定路径
def save_to_csv(pcap_input, csv_output):
    df = pcap_to_df(pcap_input)  # 使用传入的输入路径
    if df.empty:
        # 抛出异常，让调用者处理
        raise ValueError(tr("no_valid_ipv4_data", "PCAP 文件未提取到有效 IPv4 数据"))

    # 流聚合与筛选
    df = df.groupby(["Source", "Destination", "Protocol", "SrcPort", "DstPort"]).agg(
        DataSize=('Length', 'sum'),
        StartTime=('Timestamp', 'min'),
        EndTime=('Timestamp', 'max')
    ).reset_index()

    df["Duration"] = df["EndTime"] - df["StartTime"]
    df = df.drop_duplicates().drop(columns=["StartTime", "EndTime"])
    df = df[df["Duration"] > 0]

    df.to_csv(csv_output, index=False)
    print(f"转换成功: {csv_output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # 调用保存函数，传入output参数
    save_to_csv(args.input, args.output)
