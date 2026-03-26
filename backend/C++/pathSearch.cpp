//
// Created by Na_Bian on 2026/3/4.
//

# include "Graph.h"
# include <limits>
# include <algorithm>
# include <queue>

using namespace std;


//函数buildPaths通过DFS算法从目标节点b回溯到起始节点a，构建所有最小拥塞路径
//参数：当前节点curr，起始节点a，前驱节点列表prev，当前路径path，所有最小拥塞路径列表all_paths
void buildPaths(const int curr, const int a, const vector<vector<int> > &prev, vector<int> &currPath,
                vector<vector<int> > &allPaths) {
    currPath.push_back(curr); //将当前节点索引添加到当前路径中
    if (curr == a) {
        //如果当前节点是起始节点a，说明已经构建出一条完整的路径，将当前路径添加到所有路径列表中
        vector<int> path = currPath; //创建当前路径的副本
        ranges::reverse(path); //反转路径
        allPaths.push_back(path); //将当前路径添加到所有路径列表中
    } else {
        //如果当前节点不是起始节点a，继续回溯到前驱节点列表中的每个前驱节点，递归调用buildPaths函数构建路径
        for (const int prev_node: prev[curr]) {
            buildPaths(prev_node, a, prev, currPath, allPaths); //递归调用，继续回溯到前驱节点
        }
    }
    currPath.pop_back(); //回溯完成后，将当前节点索引从当前路径中移除，继续构建其他路径
}

//定义优先队列元素
struct Element {
    int index; //节点索引
    double cost; //从起始节点到当前节点的路径代价
    bool operator>(const Element &other) const {
        //代价更小的元素具有更高的优先级
        return cost > other.cost;
    }
};

// 函数minCost用于寻找图中从a节点到b节点的最小代价路径，代价由匿名函数costFunc(Edge)定义
// 参数：起始节点a的IP地址、目标节点b的IP地址、一个引用参数minCostLevel用于返回最小代价路径的总代价水平，以及一个匿名函数costFunc用于计算边的代价
// 返回值：所有最小代价路径的列表，每条路径由节点索引的列表表示
vector<vector<int> > minCost(const Graph &graph, const IPAddress &ipa, const IPAddress &ipb,
                             double &minCostLevel, const function<double(const Edges::EdgeInfo &)> &costFunc) {
    //搜索起始节点a和目标节点b的索引
    const int a = graph.findVertexIndex(ipa);
    const int b = graph.findVertexIndex(ipb);

    //如果a或b不存在，返回空路径
    if (a == -1 || b == -1) {
        minCostLevel = numeric_limits<double>::max();
        return {};
    }

    //如果a和b是同一个节点，最小拥塞水平为0，直接返回一条包含a的路径
    if (a == b) {
        minCostLevel = 0;
        return {{a}}; //返回一条包含a的路径
    }

    const int n = graph.getVertexCount(); //获取图中节点的数量
    //可能有多条路径到某节点时具有相同的最小拥塞水平，因此prev需要存储所有前驱节点索引，初始化为一个空列表
    vector<vector<int> > prev(n);
    //存储从起始节点到每个节点的最短路径，初始化为无穷大
    vector dist(n, numeric_limits<double>::max());
    //存储节点访问状态

    priority_queue<Element, vector<Element>, greater<> > q; //定义一个优先队列，按照路径代价从小到大排序
    q.push({a, 0.0}); //将起始节点a加入优先队列，路径代价为0
    dist[a] = 0;

    //循环直到目标节点b被访问
    while (!q.empty()) {
        Element top = q.top(); // 获取优先队列中路径代价最小的元素，即当前路径代价最小的节点
        q.pop();
        int curr = top.index;
        double cost = top.cost;

        if (cost > dist[curr] || dist[curr] == numeric_limits<double>::max()) {
            //已经找到了一条更短的路径到达当前节点，路径代价已经过时；或者当前节点不可达，跳过当前节点
            continue;
        }

        for (const auto &edges = graph.getEdges(curr); const auto &edgeIdx: edges.getAllEdgeIndices()) {
            const auto edgeInfo = edges.getEdgeInfo(edgeIdx); //获取每条边的信息
            const int neighbor = edgeInfo.dstIndex;
            //计算当前边的拥塞水平
            const double edgeCost = costFunc(edgeInfo); // 使用 EdgeInfo 计算代价
            if (dist[curr] + edgeCost < dist[neighbor] - 1e-9) {
                //通过当前节点u到达邻居节点v的路径拥塞水平更小，更新dist和prev
                dist[neighbor] = dist[curr] + edgeCost;
                prev[neighbor] = {curr}; //覆盖邻居节点v的前驱节点列表，只保留当前节点u作为前驱节点
                q.push({neighbor, dist[neighbor]}); //将邻居节点v加入优先队列，路径代价为更新后的dist[neighbor]
            } else if (abs(dist[curr] + edgeCost - dist[neighbor]) < 1e-9) {
                //在一定误差范围内，通过当前节点u到达邻居节点v的路径拥塞水平相同，即一条等价的最短路径
                prev[neighbor].push_back(curr); //添加当前节点u到邻居节点v的前驱节点列表中
            }
        }
    }

    minCostLevel = dist[b]; //设置最小拥塞水平

    if (minCostLevel == numeric_limits<double>::max()) {
        //如果目标节点b的距离仍然是无穷大，说明无法到达b，返回空路径
        return {};
    }

    //从目标节点b回溯到起始节点a，构建所有最小拥塞路径
    vector<vector<int> > allPaths; //存储所有最小拥塞路径的列表
    vector<int> currPath; //存储当前路径的节点索引列表
    buildPaths(b, a, prev, currPath, allPaths); //调用辅助函数构建路径

    return allPaths; //返回所有最小拥塞路径的列表
}


//寻找图中从a节点到b节点的最小拥塞路径
vector<PathInfo> Graph::minCongestion(const IPAddress &ipa, const IPAddress &ipb) const {
    double minCongestionLevel; //定义一个变量来存储最小拥塞水平
    //调用通用函数minCost，传入计算边拥塞水平的代价函数，返回最小拥塞路径
    const auto paths = minCost(*this, ipa, ipb, minCongestionLevel, [](const Edges::EdgeInfo &edge) {
        //边的拥塞水平定义为边的总数据大小除以边的总持续时间，避免除以零的情况，如果持续时间为0，则将拥塞水平设置为无穷大
        return edge.totalDuration > 0
                   ? static_cast<double>(edge.totalDataSize) / static_cast<double>(edge.totalDuration)
                   : numeric_limits<double>::max();
    });
    //从paths构建路径信息列表，包含路径和路径的拥塞水平
    vector<PathInfo> pathInfos; //存储路径信息的列表
    for (const auto &path: paths) {
        //路径的拥塞水平即minCongestionLevel
        pathInfos.push_back({path, minCongestionLevel}); //将路径和路径的拥塞水平添加到路径信息列表中
    }
    return pathInfos; //返回路径信息列表
}

//函数buildPathInfos通过计算每条路径的拥塞水平，从路径列表中构建路径信息列表
vector<PathInfo> buildPathInfos(const Graph &graph, const vector<vector<int> > &paths) {
    vector<PathInfo> pathInfos; //存储路径信息的列表
    for (const auto &path: paths) {
        //遍历每条路径，计算路径的拥塞水平
        double congestionLevel = 0; //初始化路径的拥塞水平
        for (size_t i = 0; i < path.size() - 1; ++i) {
            //遍历路径上的每条边，计算路径的总拥塞水平
            const int u = path[i]; //当前节点索引
            const int v = path[i + 1]; //下一个节点索引

            //查找当前节点u到下一个节点v的边，计算边的拥塞水平并累加到路径的拥塞水平中
            const auto &edges = graph.getEdges(u); //获取当前节点u的边列表对象
            const int idx = edges.findEdgeIndex(v); //查找当前节点u到下一个节点v的边索引

            const auto &info = edges.getEdgeInfo(idx); //获取当前节点u到下一个节点v的边信息
            const double congestion = info.totalDuration > 0
                                          ? static_cast<double>(info.totalDataSize) / static_cast<double>(info.
                                                totalDuration)
                                          : numeric_limits<double>::max();

            congestionLevel += congestion; //累加边的拥塞水平到路径的总拥塞水平中
        }
        pathInfos.push_back({path, congestionLevel}); //将路径和路径的拥塞水平添加到路径信息列表中
    }
    return pathInfos; //返回路径信息列表
}

//寻找图中从a节点到b节点的最小跳数路径
vector<PathInfo> Graph::minHop(const IPAddress &ipa, const IPAddress &ipb, int &minHopCount) const {
    double minCostLevel; //定义一个变量来存储最小拥塞水平
    vector<vector<int> > paths = minCost(*this, ipa, ipb, minCostLevel, [](const Edges::EdgeInfo &) {
        return 1.0; //边的代价定义为1，表示每条边的跳数为1
    });
    minHopCount = minCostLevel == numeric_limits<double>::max()
                      ? numeric_limits<int>::max()
                      : static_cast<int>(minCostLevel); //设置最小跳数，如果无法到达则设置为无穷大
    return buildPathInfos(*this, paths); //从路径列表中构建路径信息列表，包含路径和路径的拥塞水平
}

//重载函数，寻找图中从a节点到b节点的最小跳数路径，不返回最小跳数水平
vector<PathInfo> Graph::minHop(const IPAddress &ipa, const IPAddress &ipb) const {
    int minHopCount; //定义一个变量来存储最小跳数
    return minHop(ipa, ipb, minHopCount); //调用重载的minHop函数，返回最小跳数路径信息列表
}

//寻找图中从a节点到b节点的最小代价路径，代价由匿名函数costFunc(Edge)自定义
std::vector<PathInfo> Graph::minCostCustom(const IPAddress &ipa, const IPAddress &ipb, double &minCostLevel,
                                           const std::function<double(const Edges::EdgeInfo &)> &costFunc) const {
    //调用通用函数minCost，传入自定义的代价函数，返回最小代价路径
    const auto paths = minCost(*this, ipa, ipb, minCostLevel, costFunc);
    return buildPathInfos(*this, paths); //从路径列表中构建路径信息列表，包含路径和路径的拥塞水平
}
