//
// Created by Na_Bian on 2026/3/12.
//

# ifndef NETWORKANALYZER_SUBGRAPHEXPORTER_H
# define NETWORKANALYZER_SUBGRAPHEXPORTER_H

# include <fstream>
# include <map>
# include <utility>

# include "Graph.h"

class SubgraphExporter {
    // 用于多路径导出的边信息，包含物理边和所属组索引
    // 便于在导出JSON时记录该边出现在哪些策略组中
    struct PathEdge {
        LinkInfo linkInfo;
        std::set<int> groups;

        // 用于 map 排序的比较，只比较物理属性
        bool operator<(const PathEdge &other) const {
            return linkInfo < other.linkInfo;
        }
    };

    Graph graph;

public:
    //构造函数
    explicit SubgraphExporter(Graph graph) : graph(std::move(graph)) {
    }

    //将路径集合导出为一个子图，包含所有路径上的节点和边
    void exportPathsAsSubgraph(const std::vector<PathInfo> &paths,
                               const std::string &filename = "path_subgraph") const {
        exportSubGraph(graph.convertToConnectedComponents(paths), filename); //将路径集合转换为连通分量对象，并导出JSON文件
    }

    //重载函数，将多种策略下的路径集合转换为一个子图，包含所有路径上的节点和边
    void exportPathsAsSubgraph(const std::vector<std::vector<PathInfo> > &pathsList,
                               const std::string &filename = "multiple_paths_subgraph") const {
        std::set<int> nodes; //存储三种策略下路径上的所有节点索引
        std::map<LinkInfo, std::set<int> > edgeGroups; //建立从LinkInfo到所属组的字典
        for (size_t groupIdx = 0; groupIdx < pathsList.size(); ++groupIdx) {
            for (const auto &[path, congestionLevel]: pathsList[groupIdx]) {
                for (size_t i = 0; i < path.size(); ++i) {
                    nodes.insert(path[i]);
                    if (i > 0) {
                        const int u = path[i - 1], v = path[i];
                        const auto &edgeList = graph.getEdges(u);
                        if (const int edgeIdx = edgeList.findEdgeIndex(v); edgeIdx != -1) {
                            const long long dataSize = edgeList.getEdgeInfo(edgeIdx).totalDataSize;
                            LinkInfo link{u, v, dataSize};
                            edgeGroups[link].insert(static_cast<int>(groupIdx)); //更新字典
                        }
                    }
                }
            }
        }

        // 导出 JSON
        std::ofstream file(filename);
        if (!file.is_open()) throw std::runtime_error("无法打开文件: " + filename);

        file << "{\n";

        // 节点部分
        file << "  \"nodes\": [\n";
        bool firstNode = true;
        for (const int nodeIdx: nodes) {
            if (!firstNode) file << ",\n";
            file << "    {\"id\": " << nodeIdx << R"(, "label": ")"
                    << graph.getVertexIP(nodeIdx).toString() << R"(", "group": 1})";
            firstNode = false;
        }
        file << "\n  ],\n";

        // 边部分
        file << "  \"links\": [\n";
        bool firstEdge = true;
        for (const auto &[link, groups]: edgeGroups) {
            if (!firstEdge) file << ",\n";
            file << "    {\"source\": " << link.srcIndex << ", \"target\": " << link.dstIndex
                    << ", \"value\": " << link.dataSize << ", \"groups\": ["; //新增groups字段
            bool firstGroup = true;
            for (int g: groups) {
                if (!firstGroup) file << ",";
                file << g;
                firstGroup = false;
            }
            file << "]}";
            firstEdge = false;
        }
        file << "\n  ]\n";
        file << "}";
        file.close();
    }

    //将星形结构信息转换为一个子图
    void exportStarStructureAsSubgraph(const std::vector<StarStructure> &stars,
                                       const std::string &filename = "star_subgraph") const {
        std::vector<ConnectedComponents> components;
        //将每个星型结构转换为一个连通分量
        for (const auto &star: stars) {
            ConnectedComponents comp;
            const int centerIndex = graph.findVertexIndex(star.centerNode);
            if (centerIndex == -1) continue; // 跳过找不到中心节点的星型结构
            comp.nodes.insert(centerIndex); // 将中心节点索引添加到连通分量的节点列表中

            for (const auto &[neighborIP, dataSize]: star.neighborNodes) {
                const int neighborIndex = graph.findVertexIndex(neighborIP);
                if (neighborIndex == -1) continue; // 跳过找不到邻居节点的星型结构
                comp.nodes.insert(neighborIndex); // 将邻居节点索引添加到连通分量的节点列表中

                comp.edges.insert({centerIndex, neighborIndex, dataSize});
            }
            components.push_back(std::move(comp)); // 将构建好的连通分量添加到结果列表中
        }
        exportSubGraph(components, filename); // 将所有连通分量导出为JSON文件
    }

    //将端口扫描攻击者集合导出为子图
    void exportPortScannersAsSubgraph(const std::set<std::tuple<IPAddress, int, double> > &scanners,
                                      const std::string &filename = "scanner_subgraph") const {
        std::vector<ConnectedComponents> components;
        //将每个端口扫描攻击者转换为一个连通分量
        for (const auto &scannerIP: scanners | std::views::transform([](const auto &tup) {
            return std::get<0>(tup);
        })) {
            ConnectedComponents comp;
            const int scannerIndex = graph.findVertexIndex(scannerIP);
            if (scannerIndex == -1) continue; // 跳过找不到攻击者节点的IP地址
            comp.nodes.insert(scannerIndex); // 将攻击者节点索引添加到连通分量的节点列表中

            // 查找攻击者节点的所有邻居节点，并将它们添加到连通分量中
            for (const auto &[neighborIndex, info]: graph.analyzeNeighbors(scannerIP)) {
                comp.nodes.insert(neighborIndex); // 将邻居节点索引添加到连通分量的节点列表中
                const long long dataSize = info.InData + info.OutData; // 计算攻击者节点与邻居节点之间的总流量
                comp.edges.insert({scannerIndex, neighborIndex, dataSize}); // 将边的信息添加到连通分量的边列表中
            }
            components.push_back(std::move(comp)); // 将构建好的连通分量添加到结果列表中
        }
        exportSubGraph(components, filename); // 将所有连通分量导出为JSON文件
    }

    //将DDoS攻击目标信息转换为一个子图
    void exportDDoSTargetsAsSubgraph(const std::set<std::tuple<IPAddress, int, long long> > &targets,
                                     const std::string &filename = "ddos_subgraph") const {
        std::vector<ConnectedComponents> components;
        //将每个DDoS攻击目标转换为一个连通分量
        for (const auto &targetIP: targets | std::views::transform([](const auto &tup) {
            return std::get<0>(tup);
        })) {
            ConnectedComponents comp;
            const int targetIndex = graph.findVertexIndex(targetIP);
            if (targetIndex == -1) continue; // 跳过找不到攻击目标节点的IP地址
            comp.nodes.insert(targetIndex); // 将攻击目标节点索引添加到连通分量的节点列表中

            // 查找攻击目标节点的所有邻居节点，并将它们添加到连通分量中
            for (const auto &[neighborIndex, info]: graph.analyzeNeighbors(targetIP)) {
                comp.nodes.insert(neighborIndex); // 将邻居节点索引添加到连通分量的节点列表中
                const long long dataSize = info.InData + info.OutData; // 计算攻击目标节点与邻居节点之间的总流量
                comp.edges.insert({targetIndex, neighborIndex, dataSize}); // 将边的信息添加到连通分量的边列表中
            }
            components.push_back(std::move(comp)); // 将构建好的连通分量添加到结果列表中
        }
        exportSubGraph(components, filename); // 将所有连通分量导出为JSON文件
    }

    //函数exportViolationsAsSubgraph用于将违反规则的记录导出为一个包含违规节点和边的子图，并保存为JSON文件
    void exportViolationsAsSubgraph(const IPAddress &targetIP, const std::set<ViolationRecord> &violations,
                                    const std::string &filename = "violations_subgraph.json") const {
        std::set<int> nodes;
        if (const int targetIdx = graph.findVertexIndex(targetIP); targetIdx != -1)
            nodes.insert(targetIdx);
        for (const auto &v: violations) {
            if (const int neighborIdx = graph.findVertexIndex(v.getDstIP()); neighborIdx != -1)
                nodes.insert(neighborIdx);
        }
        // 构建子图，包含违规节点之间的边
        ConnectedComponents comp;
        comp.nodes = nodes;
        for (const int u: nodes) {
            const auto &edges = graph.getEdges(u);
            for (int edgeIdx: edges.getAllEdgeIndices()) {
                if (auto info = edges.getEdgeInfo(edgeIdx); nodes.contains(info.dstIndex)) {
                    comp.edges.insert({u, info.dstIndex, info.totalDataSize});
                }
            }
        }
        exportSubGraph(comp, filename);
    }

    //将子图信息导出为JSON文件
    void exportSubGraph(const IPAddress &targetIP, const std::string &filename = "subgraph.json") const {
        const auto component = graph.findConnectedComponents(targetIP); // 查找指定节点的连通分量
        exportSubGraph(component, filename); // 将找到的连通分量导出为JSON文件
    }

    //重载函数，将指定连通分量导出为JSON文件
    void exportSubGraph(const ConnectedComponents &component, const std::string &filename = "subgraph.json") const {
        std::ofstream file(filename);
        if (!file.is_open()) throw std::runtime_error("无法打开文件: " + filename);

        file << "{\n";

        // 写入节点信息
        file << "  \"nodes\": [\n";
        bool firstNode = true;
        for (const int nodeIdx: component.nodes) {
            if (!firstNode) file << ",\n";

            const std::string ipStr = graph.getVertexIP(nodeIdx).toString();
            // 建议：统一换行符的位置，让输出更整洁
            file << "    {\"id\": " << nodeIdx << R"(, "label": ")" << ipStr << R"(", "group": 1})";

            firstNode = false;
        }
        file << "\n  ],\n";

        // 写入边信息
        file << "  \"links\": [\n";
        bool firstEdge = true;
        for (const auto &edge: component.edges) {
            if (!firstEdge) file << ",\n";

            const auto &[srcIndex, dstIndex, dataSize] = edge;
            file << "    {\"source\": " << srcIndex << ", \"target\": " << dstIndex << ", \"value\": " << dataSize <<
                    "}";

            firstEdge = false;
        }
        file << "\n  ]\n";

        file << "}";
        file.close();
    }

    //重载函数，将不同的连通分量导出为JSON文件
    void exportSubGraph(const std::vector<ConnectedComponents> &components,
                        const std::string &filename = "subgraph.json") const {
        std::ofstream file(filename);
        if (!file.is_open()) throw std::runtime_error("无法打开文件: " + filename);

        file << "{\n";

        // 写入节点信息
        file << "  \"nodes\": [\n";
        bool firstNode = true;
        for (size_t i = 0; i < components.size(); ++i) {
            const int group = static_cast<int>(i + 1); // 以连通分量索引作为组号
            for (const int nodeIdx: components[i].nodes) {
                if (!firstNode) {
                    file << ",\n";
                }
                const std::string ipStr = graph.getVertexIP(nodeIdx).toString();
                file << "    {\"id\": " << nodeIdx << R"(, "label": ")" << ipStr << R"(", "group": )" << group << "}";
                firstNode = false;
            }
        }
        file << "\n  ],\n";

        // 写入边信息
        file << "  \"links\": [\n";
        bool firstEdge = true;
        for (const auto &comp: components) {
            for (const auto &edge: comp.edges) {
                if (!firstEdge) {
                    file << ",\n"; // 只有非首个边前才加逗号
                }
                const auto &[srcIndex, dstIndex, dataSize] = edge;
                file << "    {\"source\": " << srcIndex << ", \"target\": " << dstIndex << ", \"value\": " << dataSize
                        <<
                        "}";
                firstEdge = false;
            }
        }
        file << "\n  ]\n";

        file << "}";
        file.close();
    }

    //将所有互斥的连通分量导出为JSON文件
    void exportFullGraph(const std::string &filename = "subGraph.json") const {
        const auto allComponents = graph.findAllComponents(); // 查找图中所有的连通分量
        exportSubGraph(allComponents, filename); // 将所有连通分量导出为JSON文件
    }
};

# endif //NETWORKANALYZER_SUBGRAPHEXPORTER_H
