//
// Created by Na_Bian on 2026/3/2.
//

# ifndef NetworkAnalyzer_GRAPH_H
# define NetworkAnalyzer_GRAPH_H

# include "vertices.h"

# include <functional>
# include <cmath>
# include <thread>

//路径信息表示，包含路径上节点索引的列表和路径的拥塞水平
struct PathInfo {
    std::vector<int> path; //路径上节点索引的列表
    double congestionLevel; //路径的拥塞水平
};

//邻居信息表示，包含与邻居节点通信使用过的所有源端口号和目的端口号的组合，以及对邻居而言的入流量和出流量
struct NeighborInfo {
    std::set<std::tuple<uint8_t, uint16_t, uint16_t> > ports; //与邻居节点通信使用过的所有源端口号和目的端口号的组合，存储为一个包含协议类型、源端口号和目的端口号的元组集合
    long long InData = 0; //对邻居而言的入流量，即当前节点发送给邻居节点的流量
    long long OutData = 0; //对邻居而言的出流量，即邻居节点发送给当前节点的流量
};

//星型结构表示，包含中心节点的IP地址、邻居节点的IP地址列表、度数和中心节点与邻居节点之间的总流量
struct StarStructure {
    IPAddress centerNode; //中心节点的IP地址
    std::vector<std::pair<IPAddress, long long> > neighborNodes; //邻居节点的IP地址列表和与中心节点之间的流量
    long long totalData; //中心节点与邻居节点之间的总流量
};

//连通分量信息表示，包含连通分量中节点的索引列表和边的信息列表
struct LinkInfo {
    int srcIndex; //边的源节点索引
    int dstIndex; //边的目的节点索引
    long long dataSize; //边的总数据流量大小

    //重载<运算符，使LinkInfo对象可以存储在std::set中，并按照srcIndex、dstIndex和DataSize进行排序
    bool operator<(const LinkInfo &other) const {
        if (srcIndex != other.srcIndex) return srcIndex < other.srcIndex;
        if (dstIndex != other.dstIndex) return dstIndex < other.dstIndex;
        return dataSize < other.dataSize;
    }
};

struct ConnectedComponents {
    std::set<int> nodes; // 存储连通分量中节点的索引集合
    std::set<LinkInfo> edges; // 存储连通分量中边的信息集合
};

//网络拓扑图类，管理整个图的结构，并提供添加记录和分析邻居的功能
class Graph {
    Vertices verticesList; // 节点列表对象

    void checkIndex(const int idx) const {
        if (idx < 0 || idx >= verticesList.getVertexCount())
            throw std::out_of_range("节点索引越界: " + std::to_string(idx));
    }

public:
    // 默认构造函数返回一个空图
    Graph() = default;

    // 基本查询接口
    [[nodiscard]] int getVertexCount() const { return verticesList.getVertexCount(); }

    [[nodiscard]] int findVertexIndex(const IPAddress &ip) const { return verticesList.findVertexIndex(ip); }

    // 获取指定索引节点的IP地址
    [[nodiscard]] IPAddress getVertexIP(const int vertexIndex) const {
        checkIndex(vertexIndex);
        return verticesList.getIP(vertexIndex);
    }

    //为节点列表预分配内存，转发给Vertices类的reserve方法
    void reserve(const size_t capacity) { verticesList.reserve(capacity); }

    // 获取指定索引节点的边列表对象
    [[nodiscard]] const Edges &getEdges(const int index) const {
        checkIndex(index);
        return verticesList.getEdges(index);
    }

    // 对节点进行流量排序
    [[nodiscard]] std::vector<std::pair<IPAddress, long long> > getNodesSortedByTotalTraffic() const;

    [[nodiscard]] std::vector<std::pair<IPAddress, long long> > getNodesWithHTTPSortedByTraffic() const;

    [[nodiscard]] std::vector<std::tuple<IPAddress, long long, double> > getNodesWithOutRatioAbove(
        double threshold = 0.8) const;

    // 添加边会话记录
    // 参数：源IP地址、目的IP地址、协议类型、源端口号、目的端口号、数据包大小和会话持续时间
    void addRecord(const IPAddress &srcIP, const IPAddress &dstIP, uint8_t protocol, uint16_t srcPort, uint16_t dstPort,
                   int dataSize, double duration);

    // 端口扫描攻击者检测
    // 端口扫描攻击者通常会对同一个IP的大量不同端口发送探测包，寻找开放的服务
    [[nodiscard]] std::set<std::tuple<IPAddress, int, double> > detectPortScanners(int portThreshold = 20,
        double outRatioThreshold = 0.8) const;

    //DDoS攻击目标检测
    //DDoS攻击目标通常在短时间内的入流量极大，且同时与海量不同的IP通信
    [[nodiscard]] std::set<std::tuple<IPAddress, int, long long> > detectDDoSTargets(int neighborThreshold = 20,
        long long inDataThreshold = 1LL << 30) const;

    //函数minCongestion用于寻找图中从a节点到b节点的最小拥塞路径
    //参数：起始节点a的IP地址、目标节点b的IP地址
    //返回值：所有最小拥塞路径的列表，每条路径表示为一个包含路径上节点索引的列表和路径的拥塞水平
    [[nodiscard]] std::vector<PathInfo> minCongestion(const IPAddress &ipa, const IPAddress &ipb) const;

    //函数minHop用于寻找图中从a节点到b节点的最小跳数路径
    //参数：图对象、起始节点a的IP地址、目标节点b的IP地址
    //返回值：所有最小跳数路径信息的列表，每条路径信息包含路径上节点索引的列表和路径的拥塞水平
    [[nodiscard]] std::vector<PathInfo> minHop(const IPAddress &ipa, const IPAddress &ipb) const;

    //重载函数minHop，增加参数minHopCount用于返回最小跳数路径的跳数
    std::vector<PathInfo> minHop(const IPAddress &ipa, const IPAddress &ipb, int &minHopCount) const;

    //函数minCostCustom用于寻找图中从a节点到b节点的最小代价路径，代价由匿名函数costFunc(Edge)自定义，默认基于边的安全性
    std::vector<PathInfo> minCostCustom(
        const IPAddress &ipa, const IPAddress &ipb, double &minCostLevel,
        const std::function<double(const Edges::EdgeInfo &)> &costFunc = [](const Edges::EdgeInfo &edge) {
            const double base = Edges::isSecure(edge) ? 1.0 : 10.0; // 安全边的代价为1，不安全边的代价为10

            int totalPortPairs = 0;
            for (const auto &stats: edge.protocolStats | std::views::values) {
                totalPortPairs += static_cast<int>(stats.ports.size());
            }
            // 根据边上使用过的不同端口组合数量增加代价，惩罚可能的端口扫描行为
            const double portScanPenalty = 1.0 + std::min(2.0, std::log2(1.0 + totalPortPairs / 20.0));

            return base * portScanPenalty;
        }) const;

    //计算图中所有节点的邻居信息
    //返回值：一个包含邻居索引和邻居信息的字典列表
    [[nodiscard]] std::vector<std::unordered_map<int, NeighborInfo> > analyzeNeighbors(
        unsigned int numThreads = std::thread::hardware_concurrency() >= 4 ? 4 : std::thread::hardware_concurrency())
    const;

    //重载函数analyzeNeighbors，查找单个节点的邻居信息
    //参数：节点IP
    //返回值：一个包含邻居索引和邻居信息的字典
    [[nodiscard]] std::unordered_map<int, NeighborInfo> analyzeNeighbors(const IPAddress &targetIP) const;

    //函数findStarStructures用于在图中寻找星型结构
    //参数：度数阈值degreeThreshold
    //返回值：包含所有星型结构的列表
    [[nodiscard]] std::vector<StarStructure> findStarStructures(int degreeThreshold = 20) const;

    //寻找指定节点的连通分量
    //支持传入预先计算的所有节点的邻居信息，避免重复计算
    [[nodiscard]] ConnectedComponents findConnectedComponents(
        const IPAddress &targetIP, const std::vector<std::unordered_map<int, NeighborInfo> > &allNeighbors = {}) const;

    //寻找子图中所有互斥的连通分量
    [[nodiscard]] std::vector<ConnectedComponents> findAllComponents() const;

    //将路径集合转换为ConnectedComponents对象
    [[nodiscard]] ConnectedComponents convertToConnectedComponents(const std::vector<PathInfo> &paths) const;
};


# endif //NetworkAnalyzer_GRAPH_H
