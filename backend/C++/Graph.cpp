//
// Created by Na_Bian on 2026/3/7.
//

# include "Graph.h"
# include <ranges>
# include <future>
# include <unordered_set>
# include <queue>
# include <fstream>
# include <set>

using namespace std;

//获取所有节点按照总流量排序的列表
vector<pair<IPAddress, long long> > Graph::getNodesSortedByTotalTraffic() const {
    // 转发调用Vertices类中的sortTraffic函数，获取所有节点按照总流量排序的列表
    return verticesList.sortTraffic();
}

//获取所有节点按照HTTPS流量排序的列表
vector<pair<IPAddress, long long> > Graph::getNodesWithHTTPSortedByTraffic() const {
    // 转发调用Vertices类中的sortTrafficHasHTTPS函数，获取包含HTTPS连接的节点按照HTTPS流量排序的列表
    return verticesList.sortTrafficHasHTTPS();
}

//获取所有节点按照出流量占总流量比例排序的列表，过滤掉比例低于指定阈值的节点
vector<tuple<IPAddress, long long, double> > Graph::getNodesWithOutRatioAbove(
    const double threshold) const {
    // 转发调用Vertices类中的sortTrafficByOutRatio函数，获取所有节点按照出流量占总流量比例排序的列表，过滤掉比例低于指定阈值的节点
    return verticesList.sortTrafficByOutRatio(threshold);
}


//添加边会话记录
void Graph::addRecord(const IPAddress &srcIP, const IPAddress &dstIP, const uint8_t protocol, const uint16_t srcPort,
                      const uint16_t dstPort, const int dataSize,
                      const double duration) {
    //查找源IP地址对应的节点
    int srcIndex = verticesList.findVertexIndex(srcIP);
    if (srcIndex == -1) {
        //如果源IP地址不存在，则添加新节点
        verticesList.addVertex(srcIP);
        srcIndex = verticesList.getVertexCount() - 1; // 获取源IP地址节点的索引
    }

    //查找目的IP地址对应的节点
    int dstIndex = verticesList.findVertexIndex(dstIP);
    if (dstIndex == -1) {
        //如果目的IP地址不存在，则添加新节点
        verticesList.addVertex(dstIP);
        dstIndex = verticesList.getVertexCount() - 1; // 获取目的IP地址节点的索引
    }

    //更新节点的流量统计数据
    verticesList.updateOutData(srcIndex, dataSize); // 更新源节点的总出流量
    verticesList.updateInData(dstIndex, dataSize); // 更新目的节点的总入流量

    //检查是否为HTTPS连接
    if (protocol == 6 && dstPort == 443 || srcPort == 443) {
        verticesList.updateHTTPSData(srcIndex, dataSize); // 更新源节点的总HTTPS流量
        verticesList.updateHTTPSData(dstIndex, dataSize); // 更新目的节点的总HTTPS流量
    }
    //在源IP地址对应的节点的边链表中添加或合并当前边
    verticesList.addEdgeForIndex(srcIndex, dstIndex, protocol, srcPort, dstPort, dataSize, duration);
}

//端口扫描攻击者检测
set<tuple<IPAddress, int, double> > Graph::detectPortScanners(const int portThreshold,
                                                              const double outRatioThreshold) const {
    set<tuple<IPAddress, int, double> > scanners;
    const int n = verticesList.getVertexCount();
    const auto ratio = getNodesWithOutRatioAbove(outRatioThreshold);

    for (int i = 0; i < n; ++i) {
        // 遍历每个节点
        const auto &edges = verticesList.getEdges(i); // 获取当前节点的所有出边

        for (const int edgeIdx: edges.getAllEdgeIndices()) {
            const auto &edgeInfo = edges.getEdgeInfo(edgeIdx);

            // 对该节点与某个邻居节点之间的所有通信记录，统计不同目的端口的总数
            set<uint16_t> uniqueDstPorts;
            for (const auto &stats: edgeInfo.protocolStats | std::views::values) {
                for (const auto &dstPort: stats.ports | std::views::values) {
                    uniqueDstPorts.insert(dstPort);
                }
            }

            // 如果对同一个邻居发起了过多目的端口的连接
            if (uniqueDstPorts.size() > portThreshold) {
                // 如果节点出流量占总流量的比例超过指定阈值，则判定为端口扫描攻击者
                const auto it = ranges::find(ratio, verticesList.getIP(i), [](const auto &tup) {
                    return get<0>(tup);
                });
                if (it != ratio.end()) {
                    // 将攻击者的IP地址、不同目的端口数量和出流量占比添加到结果集合中
                    scanners.insert({verticesList.getIP(i), uniqueDstPorts.size(), get<2>(*it)});
                }
                break;
            }
        }
    }
    return scanners;
}

//DDoS攻击目标检测
set<tuple<IPAddress, int, long long> > Graph::detectDDoSTargets(const int neighborThreshold,
                                                                const long long inDataThreshold) const {
    set<tuple<IPAddress, int, long long> > targets;
    const int n = verticesList.getVertexCount();

    const auto allNeighbors = analyzeNeighbors(); // 获取图中每个节点的邻居信息列表
    for (int i = 0; i < n; ++i) {
        if (verticesList.getTotalInData(i) > inDataThreshold && allNeighbors[i].size() > neighborThreshold) {
            //如果节点的入流量超过指定阈值，并且与大量不同的邻居节点通信，则判定为DDoS攻击目标
            targets.insert({verticesList.getIP(i), allNeighbors[i].size(), verticesList.getTotalInData(i)});
        }
    }

    return targets;
}

//分析图中所有节点的邻居信息
vector<unordered_map<int, NeighborInfo> > Graph::analyzeNeighbors(const unsigned int numThreads) const {
    const int n = verticesList.getVertexCount(); // 获取节点数量
    //创建一个列表用于存储每个节点的邻居信息，邻居信息以字典形式存储，
    //键为邻居节点索引，值为一个结构体，包含与邻居节点通信使用过的源端口号集合、目的端口号集合和总流量
    vector<unordered_map<int, NeighborInfo> > neighbors(n);

    // 使用互斥锁保护邻居信息列表，确保线程安全地更新邻居信息
    vector<unique_ptr<mutex> > nodeMutexes(n);
    for (int i = 0; i < n; ++i) nodeMutexes[i] = make_unique<mutex>();

    vector<future<void> > futures; // 存储线程的future对象

    const int base = n / static_cast<int>(numThreads); // 计算每个线程需要处理的节点数量
    const int remainder = n % static_cast<int>(numThreads); // 计算剩余的节点数量

    //分块并行处理每个节点的邻居信息
    int start = 0; // 当前线程处理的起始节点索引
    int end = -1; // 当前线程处理的结束节点索引
    for (int i = 0; i < static_cast<int>(numThreads); ++i) {
        //前remainder个线程处理base+1个节点，剩余线程处理base个节点
        const int nodesToRead = i < remainder ? base + 1 : base;
        start = end + 1;
        end = start + nodesToRead - 1;
        if (start > end) break;
        futures.push_back(std::async(launch::async, [this, start, end, &neighbors, &nodeMutexes]() {
            //遍历从start到end范围内的每个节点索引u
            for (int u = start; u <= end; ++u) {
                const auto &edges = verticesList.getEdges(u); // 获取当前节点的边列表对象
                //遍历当前节点的所有出边
                for (const int edgeIdx: edges.getAllEdgeIndices()) {
                    // 获取当前边的信息
                    const auto &edgeInfo = edges.getEdgeInfo(edgeIdx);
                    const int v = edgeInfo.dstIndex;
                    const long long dataSize = edgeInfo.totalDataSize;
                    const auto &statsMap = edgeInfo.protocolStats; // 协议统计数据

                    // 更新u的邻居信息
                    {
                        lock_guard lock(*nodeMutexes[u]); //给u的邻居信息加锁，确保线程安全地更新信息
                        neighbors[u][v].InData += dataSize;
                        for (const auto protocol: statsMap | std::views::keys) {
                            const auto &stats = statsMap.at(protocol);
                            for (const auto &[srcPort, dstPort]: stats.ports) {
                                neighbors[u][v].ports.insert({protocol, srcPort, dstPort});
                            }
                        }
                    }
                    // 更新v的邻居信息
                    {
                        lock_guard lock(*nodeMutexes[v]); //给v的邻居信息加锁，确保线程安全地更新信息
                        neighbors[v][u].OutData += dataSize;
                        for (const auto protocol: statsMap | std::views::keys) {
                            const auto &stats = statsMap.at(protocol);
                            for (const auto &[srcPort, dstPort]: stats.ports) {
                                neighbors[v][u].ports.insert({protocol, srcPort, dstPort});
                            }
                        }
                    }
                }
            }
        }));
    }

    for (auto &f: futures) f.wait(); // 等待所有线程完成计算

    return neighbors; // 返回每个节点的邻居信息列表
}

//查找单个节点的邻居信息
unordered_map<int, NeighborInfo> Graph::analyzeNeighbors(const IPAddress &targetIP) const {
    const int n = verticesList.getVertexCount(); // 获取节点数量
    const int targetIndex = verticesList.findVertexIndex(targetIP);
    if (targetIndex == -1) throw runtime_error("找不到目标IP");
    unordered_map<int, NeighborInfo> neighbors; // 创建一个字典用于存储指定节点的邻居信息

    //遍历自己的边列表 vertex -> neighbor
    const auto &ownEdges = verticesList.getEdges(targetIndex); // 获取指定节点的边列表对象
    for (const auto &ownEdgeIdx: ownEdges.getAllEdgeIndices()) {
        const int neighborIndex = ownEdges.getEdgeInfo(ownEdgeIdx).dstIndex; // 获取边的目的节点索引
        //获取通信 vertex -> neighborIndex 中所有使用过的源端口号、目的端口号，添加到邻居信息中
        const auto edgeInfo = ownEdges.getEdgeInfo(ownEdgeIdx).protocolStats;
        for (const auto &protocol: edgeInfo | std::views::keys) {
            for (const auto &[srcPort, dstPort]: edgeInfo.at(protocol).ports) {
                neighbors[neighborIndex].ports.insert({protocol, srcPort, dstPort});
            }
        }
        //累加通信 vertex -> neighborIndex 的总流量到邻居信息中
        neighbors[neighborIndex].InData += ownEdges.getEdgeInfo(ownEdgeIdx).totalDataSize;
    }

    //遍历图中的每个节点 neighbor -> target
    for (int v = 0; v < n; ++v) {
        if (v == targetIndex) continue; // 跳过自己
        const auto &edges = verticesList.getEdges(v); // 获取当前节点的边列表对象

        //查找是否存在通信 neighbor -> vertex 的边
        if (const int edgeIdx = edges.findEdgeIndex(targetIndex); edgeIdx != -1) {
            //获取通信 neighbor -> vertex 中所有使用过的源端口号、目的端口号，添加到邻居信息中
            const auto edgeInfo = edges.getEdgeInfo(edgeIdx).protocolStats;
            for (const auto &protocol: edgeInfo | std::views::keys) {
                for (const auto &[srcPort, dstPort]: edgeInfo.at(protocol).ports) {
                    neighbors[v].ports.insert({protocol, srcPort, dstPort});
                }
            }

            //累加通信 neighbor -> vertex 的总流量到邻居信息中
            neighbors[v].OutData += edges.getEdgeInfo(edgeIdx).totalDataSize;
        }
    }
    return neighbors; // 返回指定节点的邻居信息字典
}

//查找星型结构
vector<StarStructure> Graph::findStarStructures(const int degreeThreshold) const {
    vector<StarStructure> starStructures; // 创建一个列表用于存储找到的星型结构
    const auto neighbors = analyzeNeighbors(); // 获取图中每个节点的邻居信息列表
    //遍历每个节点的邻居列表，寻找满足条件的星型结构
    for (int i = 0; i < neighbors.size(); ++i) {
        const auto &currNeighbors = neighbors[i];

        const IPAddress centerNode = verticesList.getIP(i); // 中心节点的IP地址
        const long long totalData = verticesList.getTotalTraffic(i); // 中心节点与邻居节点之间的总流量
        vector<pair<IPAddress, long long> > neighborIPs; // 存储满足条件的邻居节点的IP地址列表和与中心节点之间的流量

        //检查邻居中叶子数是否超过度数阈值
        int totalLeaves = 0;
        for (const auto &[neighborIndex, info]: currNeighbors) {
            if (neighbors[neighborIndex].size() == 1) {
                // 叶子节点
                totalLeaves++;
                //流量
                const long long leafData = info.InData + info.OutData;
                // 将叶子邻居节点的IP地址添加到列表中
                neighborIPs.emplace_back(verticesList.getIP(neighborIndex), leafData);
            }
        }

        //如果叶子数超过度数阈值，则构建星型结构信息并添加到结果列表中
        if (totalLeaves > degreeThreshold) {
            starStructures.push_back({centerNode, std::move(neighborIPs), totalData});
        }
    }
    return starStructures; //返回找到的星型结构列表
}

//寻找指定节点的连通分量
ConnectedComponents Graph::findConnectedComponents(
    const IPAddress &targetIP, const vector<unordered_map<int, NeighborInfo> > &allNeighbors) const {
    const int targetIndex = verticesList.findVertexIndex(targetIP);
    if (targetIndex == -1) throw runtime_error("找不到目标IP");

    //用BFS算法查找指定节点的连通分量
    ConnectedComponents results;
    unordered_set<int> discovered; // 存储已访问的节点索引
    queue<int> q; // 辅助队列

    if (allNeighbors.empty()) {
        //如果没有预先计算的邻居信息，则调用analyzeNeighbors计算所有节点的邻居信息
        const auto neighbors = analyzeNeighbors();
        return findConnectedComponents(targetIP, neighbors);
    }

    q.push(targetIndex); // 将起始节点加入队列
    discovered.insert(targetIndex); // 将起始节点标记为已访问

    while (!q.empty()) {
        const int curr = q.front(); // 获取队列头部的节点索引
        q.pop(); // 从队列中移除当前节点索引
        results.nodes.insert(curr); // 将当前节点索引添加到连通分量的节点列表中

        // 获取当前节点的邻居信息
        const auto &neighbors = allNeighbors[curr];
        //遍历当前节点的所有邻居
        for (const auto &neighborIndex: neighbors | views::keys) {
            if (!discovered.contains(neighborIndex)) {
                //邻居节点未被访问过，则将其加入队列并标记为已访问
                discovered.insert(neighborIndex);
                q.push(neighborIndex);
            }
        }
    }
    //构建连通分量中边的信息列表
    for (const int nodeIndex: results.nodes) {
        for (const auto &edgeIdx: verticesList.getEdges(nodeIndex).getAllEdgeIndices()) {
            const auto &edge = verticesList.getEdges(nodeIndex).getEdgeInfo(edgeIdx);
            if (results.nodes.contains(edge.dstIndex)) {
                //边的目的节点也在连通分量中，添加边的信息到连通分量的边列表中
                results.edges.insert({nodeIndex, edge.dstIndex, edge.totalDataSize});
            }
        }
    }
    return results; // 返回指定节点的连通分量信息
}

//寻找子图中所有互斥的连通分量
vector<ConnectedComponents> Graph::findAllComponents() const {
    const int nodeCount = verticesList.getVertexCount();
    vector<ConnectedComponents> results;
    vector visited(nodeCount, false); // 存储每个节点是否已访问过

    const auto allNeighbors = analyzeNeighbors(); // 计算所有节点的邻居信息

    for (int i = 0; i < nodeCount; ++i) {
        // 当前节点未被访问过，是一个新的连通分量的起始节点
        if (!visited[i]) {
            // 查找以当前节点为起始节点的连通分量
            ConnectedComponents comp = findConnectedComponents(verticesList.getIP(i), allNeighbors);
            // 标记连通分量中的所有节点为已访问
            for (const int nodeIndex: comp.nodes) {
                visited[nodeIndex] = true;
            }
            results.push_back(std::move(comp)); // 将找到的连通分量添加到结果列表中
        }
    }
    return results;
}

//将路径集合导出为子图
ConnectedComponents Graph::convertToConnectedComponents(const vector<PathInfo> &paths) const {
    set<int> nodes;
    set<LinkInfo> edges;
    for (const auto &path: paths | views::transform(&PathInfo::path)) {
        for (size_t i = 0; i < path.size(); ++i) {
            nodes.insert(path[i]);
            if (i > 0) {
                const int u = path[i - 1];
                const int v = path[i];
                // 查找u到v的边，获取数据大小
                const auto &edgeList = verticesList.getEdges(u);
                if (const int edgeIdx = edgeList.findEdgeIndex(v); edgeIdx != -1) {
                    const long long dataSize = edgeList.getEdgeInfo(edgeIdx).totalDataSize;
                    edges.insert({u, v, dataSize});
                }
            }
        }
    }
    // 构建ConnectedComponents对象
    return {nodes, edges};
}
