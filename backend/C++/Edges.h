//
// Created by Na_Bian on 2026/3/7.
//

# ifndef NETWORKANALYZER_EDGES_H
# define NETWORKANALYZER_EDGES_H

# include <set>
# include <cstdint>
# include <ranges>
# include <unordered_map>
# include <vector>


//边集合类，管理每个节点的边列表
class Edges {
public:
	// 协议统计数据
	struct ProtocolStats {
		long long dataSize = 0; // 数据包大小
		double duration = 0.0; // 会话持续时间
		std::set<std::pair<uint16_t, uint16_t> > ports; // 与该协议相关的端口号集合，存储所有通信使用过的源端口号和目的端口号的组合
	};

	// 边的只读信息
	struct EdgeInfo {
		int dstIndex;
		long long totalDataSize;
		double totalDuration;
		const std::unordered_map<uint8_t, ProtocolStats>& protocolStats; // 引用
	};

	// 判断边是否包含安全协议（如HTTPS、SSH等），如果包含则返回true，否则返回false
	static bool isSecure(const EdgeInfo& edge) {
		static const std::set<uint16_t> securePorts = {
			//常见安全协议的端口号列表
			//HTTPS(443)、SSH(22)、SMTPS(465)、IMAPS(993)、POP3S(995)、FTPS(990/989)、
			//QUIC(8443)、SMTP(587)、OpenVPN(1194)、IPSec(500/4500)、WireGuard(51820)
			443, 22, 465, 993, 995, 853, 636, 990, 989, 8443, 587, 1194, 500, 4500, 51820
		};
		for (const auto& stats : edge.protocolStats | std::views::values) {
			for (const auto& [srcPort, dstPort] : stats.ports) {
				if (securePorts.contains(dstPort) || securePorts.contains(srcPort))
					return true;
			}
		}
		return false;
	}

private:
	//定义边表示，包含目的IP地址索引、统计数据和协议统计数据
	struct Edge {
		int dstIndex; // 目的IP地址在节点列表中的索引
		long long totalDataSize; // 总数据流量大小
		double totalDuration; // 总会话持续时间
		std::unordered_map<uint8_t, ProtocolStats> protocolStats; // key为协议类型，value为该协议的统计数据
	};

	std::vector<Edge> edges; // 边列表
	std::unordered_map<int, int> dstToIndex; // 缓存目的IP地址索引到边列表索引的映射，优化查找性能

	void checkIndex(const int idx) const {
		if (idx < 0 || idx >= static_cast<int>(edges.size()))
			throw std::out_of_range("边索引越界: " + std::to_string(idx));
	}

public:
	//默认构造函数，返回一个空的边列表
	Edges() = default;

	//基本查询接口
	[[nodiscard]] int getEdgeCount() const { return static_cast<int>(edges.size()); }

	//查找目的IP地址索引对应的边在边列表中的索引，若不存在则返回-1
	[[nodiscard]] int findEdgeIndex(const int dstIPIndex) const {
		const auto it = dstToIndex.find(dstIPIndex);
		return it != dstToIndex.end() ? it->second : -1;
	}

	//边属性访问器
	[[nodiscard]] EdgeInfo getEdgeInfo(const int edgeIdx) const {
		checkIndex(edgeIdx);
		const auto& [dstIndex, totalDataSize, totalDuration, protocolStats] = edges[edgeIdx];
		return { dstIndex, totalDataSize, totalDuration, protocolStats };
	}

	// 获取所有边的索引，用于遍历
	[[nodiscard]] std::vector<int> getAllEdgeIndices() const {
		std::vector<int> indices(edges.size());
		for (size_t i = 0; i < edges.size(); ++i) indices[i] = static_cast<int>(i);
		return indices;
	}

	//添加新边
	//参数：目的IP地址索引、协议类型、源端口号、目的端口号、数据包大小和会话持续时间
	void addEdge(const int dstIndex, const uint8_t protocol, const uint16_t srcPort, const uint16_t dstPort,
		const long long dataSize, const double duration) {
		//检查是否已经存在到目的IP地址的边
		if (const int it = findEdgeIndex(dstIndex); it != -1) {
			//如果边已经存在，更新统计数据
			Edge& edge = edges[it]; // 获取边列表中对应的边
			edge.totalDataSize += dataSize; // 更新总数据包大小
			edge.totalDuration += duration; // 更新总会话持续时间
			//合并协议统计数据
			auto& stats = edge.protocolStats[protocol]; // 获取当前协议的统计数据，若不存在则会自动创建
			stats.dataSize += dataSize; // 更新协议的数据包大小
			stats.duration += duration; // 更新协议的会话持续时间
			stats.ports.insert({ srcPort, dstPort }); // 将源端口号添加到协议的源端口号集合中
			return;
		}
		//否则添加新边
		edges.push_back({
			dstIndex, dataSize, duration,
			{{protocol, {dataSize, duration, {{srcPort, dstPort}}}}}
			}); // 列表初始化新边的目的IP地址索引、统计数据和协议统计数据
		dstToIndex[dstIndex] = getEdgeCount() - 1; // 更新缓存，映射目的IP地址索引到新边的索引
	}
};


# endif //NETWORKANALYZER_EDGES_H
