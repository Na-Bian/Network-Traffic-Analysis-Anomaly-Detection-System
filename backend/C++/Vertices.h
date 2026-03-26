//
// Created by Na_Bian on 2026/3/7.
//

# ifndef NETWORKANALYZER_VERTICES_H
# define NETWORKANALYZER_VERTICES_H

# include "IPAddress.h"
# include "Edges.h"

# include <algorithm>


//节点集合类，管理所有节点的添加、查找和排序
class Vertices {
    //定义节点表示，包含IP地址和边列表
    struct Vertex {
        IPAddress ipAddress; // 节点对应的IP地址
        Edges edgesList; // 每个节点维护一个边列表，存储与该节点相关的所有边
        long long totalInData; // 该节点的总入流量
        long long totalOutData; // 该节点的总出流量
        long long totalHTTPSData; // 该节点的总HTTPS流量
    };

    std::vector<Vertex> vertices; // 节点列表
    std::unordered_map<uint32_t, int> ipToIndex; // 缓存节点IP地址到节点索引的映射，优化查找性能

    void checkIndex(const int idx) const {
        if (idx < 0 || idx >= static_cast<int>(vertices.size()))
            throw std::out_of_range("节点索引越界: " + std::to_string(idx));
    }

public:
    //默认构造函数，返回一个空的节点集合
    Vertices() = default;

    //基本查询接口
    [[nodiscard]] int getVertexCount() const { return static_cast<int>(vertices.size()); }

    [[nodiscard]] int findVertexIndex(const IPAddress &ipAddress) const {
        //在缓存中查找IP地址对应的节点索引
        const auto it = ipToIndex.find(ipAddress.getIP());
        return it != ipToIndex.end() ? it->second : -1; // 如果找到则返回索引，否则返回-1表示节点不存在
    }

    // 获取指定索引节点的IP地址、边列表和流量统计数据
    [[nodiscard]] IPAddress getIP(const int index) const {
        checkIndex(index);
        return vertices[index].ipAddress;
    }

    [[nodiscard]] const Edges &getEdges(const int index) const {
        checkIndex(index);
        return vertices[index].edgesList;
    }

    [[nodiscard]] long long getTotalInData(const int index) const {
        checkIndex(index);
        return vertices[index].totalInData;
    }

    [[nodiscard]] long long getTotalOutData(const int index) const {
        checkIndex(index);
        return vertices[index].totalOutData;
    }

    [[nodiscard]] long long getTotalTraffic(const int index) const {
        checkIndex(index);
        return getTotalInData(index) + getTotalOutData(index);
    }

    [[nodiscard]] long long getTotalHTTPSData(const int index) const {
        checkIndex(index);
        return vertices[index].totalHTTPSData;
    }

    //更新指定索引节点的流量统计数据
    void updateInData(const int index, const long long dataSize) {
        checkIndex(index);
        vertices[index].totalInData += dataSize;
    }

    void updateOutData(const int index, const long long dataSize) {
        checkIndex(index);
        vertices[index].totalOutData += dataSize;
    }

    void updateHTTPSData(const int index, const long long dataSize) {
        checkIndex(index);
        vertices[index].totalHTTPSData += dataSize;
    }

    //函数reserve用于预分配节点列表的内存，以提高性能
    void reserve(const size_t capacity) { vertices.reserve(capacity); }

    //添加新节点
    void addVertex(const IPAddress &ipAddress) {
        if (findVertexIndex(ipAddress) == -1) {
            // 只有当节点不存在时才添加
            vertices.push_back({ipAddress, Edges{}, 0, 0, 0}); // 列表初始化新节点的IP地址和默认值
            ipToIndex[ipAddress.getIP()] = getVertexCount() - 1; // 更新缓存，映射新节点的IP地址到其索引
        }
    }

    //为节点index添加新边
    void addEdgeForIndex(const int index, const int dstIndex, const uint8_t protocol, const uint16_t srcPort,
                         const uint16_t dstPort, const long long dataSize, const double duration) {
        checkIndex(index);
        //转发给对应节点的边列表对象，添加或合并当前边
        vertices[index].edgesList.addEdge(dstIndex, protocol, srcPort, dstPort, dataSize, duration);
    }


    // 函数sortTraffic用于对所有节点按照流量进行排序
    // 返回一个包含(节点IP地址,总流量)元组的列表，按照节点流量从大到小排序
    [[nodiscard]] std::vector<std::pair<IPAddress, long long> > sortTraffic() const {
        std::vector<const Vertex *> ptrs;
        ptrs.reserve(vertices.size());
        for (const auto &v: vertices) {
            ptrs.push_back(&v);
        }

        // C++20引入的std::ranges::sort函数，可以对指定容器按照投影中的属性进行排序
        // 使用std::ranges::greater{}作为比较器，按照总流量从大到小排序
        std::ranges::sort(ptrs, std::ranges::greater{}, [](const Vertex *v) {
            return v->totalInData + v->totalOutData;
        });

        std::vector<std::pair<IPAddress, long long> > result;
        result.reserve(ptrs.size());
        for (const auto *v: ptrs) {
            result.emplace_back(v->ipAddress, v->totalInData + v->totalOutData);
        }
        return result;
    }

    //函数sortTrafficHasHTTPS用于对图中包含HTTPS连接的节点进行排序
    //返回一个包含(节点IP地址,HTTPS流量)元组的列表，按照节点的HTTPS流量从大到小排序
    [[nodiscard]] std::vector<std::pair<IPAddress, long long> > sortTrafficHasHTTPS() const {
        std::vector<const Vertex *> ptrs;
        for (const auto &v: vertices) {
            if (v.totalHTTPSData != 0) ptrs.push_back(&v);
        }
        std::ranges::sort(ptrs, std::ranges::greater{}, &Vertex::totalHTTPSData);
        std::vector<std::pair<IPAddress, long long> > result;
        result.reserve(ptrs.size());
        for (const auto *v: ptrs) {
            result.emplace_back(v->ipAddress, v->totalHTTPSData);
        }
        return result;
    }

    //按单向流量占比阈值outThreshold筛选节点
    //返回一个包含(节点IP地址,出流量占比)元组的列表，按照节点的总流量从大到小排序
    [[nodiscard]] std::vector<std::tuple<IPAddress, long long, double> > sortTrafficByOutRatio(const double outThreshold) const {
        std::vector<std::pair<const Vertex *, double> > ptrs;
        ptrs.reserve(vertices.size());
        for (const auto &vertex: vertices) {
            if (const long long totalData = vertex.totalInData + vertex.totalOutData; totalData > 0) {
                if (const double outRatio = static_cast<double>(vertex.totalOutData) / static_cast<double>(totalData);
                    outRatio >= outThreshold) {
                    ptrs.emplace_back(&vertex, outRatio);
                }
            }
        }
        std::ranges::sort(ptrs, std::ranges::greater{}, [](const std::pair<const Vertex *, double> &pair) {
            return pair.first->totalInData + pair.first->totalOutData;
        });

        std::vector<std::tuple<IPAddress, long long, double> > result;
        result.reserve(ptrs.size());
        for (const auto &[vertexPtr, outRatio]: ptrs) {
            result.emplace_back(vertexPtr->ipAddress, vertexPtr->totalInData + vertexPtr->totalOutData, outRatio);
        }
        return result;
    }
};


# endif //NETWORKANALYZER_VERTICES_H
