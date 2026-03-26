// main.cpp

# include <windows.h>
# include "Graph.h"
# include "CSVReader.h"
# include "CustomRule.h"
# include "SubgraphExporter.h"
# include <iostream>
# include <string>
# include <thread>    // for hardware_concurrency
# include <memory>

using namespace std;

// 辅助函数，打印程序的使用说明
void printUsage(const char *progName) {
    cerr << "用法:\n"
            << "  " << progName << " --input <file> --task <task> [选项]\n"
            << "任务:\n"
            << "  full-graph                        导出全网拓扑JSON\n"
            << "  subgraph                          导出以目标IP为中心的子图JSON\n"
            << "  flow-sort                         节点流量排序\n"
            << "  sort-type <total|https|outratio>  排序类型\n"
            << "  ratio-threshold                   出流量占比阈值\n"
            << "  min-congestion                    最小拥塞路径\n"
            << "  min-hop                           最小跳数路径\n"
            << "  min-risk                          最小风险路径\n"
            << "  compare-paths                     比较不同策略下的路径\n"
            << "  port-scan                         检测端口扫描攻击者\n"
            << "  ddos-target                       检测DDoS攻击目标\n"
            << "  star-structures                   查找星型结构\n"
            << "  custom-rule                       自定义规则检测\n"
            << "选项:\n"
            << "  --output-json <file>              输出JSON图文件（可选）\n"
            << "  --target <ip>                     目标IP（用于子图）\n"
            << "  --src <ip>                        源IP（用于路径）\n"
            << "  --dst <ip>                        目的IP（用于路径）\n"
            << "  --threshold <num>                 阈值（端口扫描、DDoS、星型结构）\n"
            << "  --in-data-threshold <num>         入流量阈值（DDoS）\n"
            << "  --threads <num>                   线程数（默认CPU核心数）\n"
            << "  --rule-target <ip>                自定义规则：目标IP\n"
            << "  --range-cidr <cidr>               自定义规则：CIDR范围\n"
            << "  --range-start <ip>                自定义规则：起始IP（与--range-end配合）\n"
            << "  --range-end <ip>                  自定义规则：结束IP\n"
            << "  --rule-type <allow|deny>          自定义规则类型（默认deny）\n"
            << "  --rule-protocol <num>             自定义规则：协议类型（可选）\n"
            << "  --rule-src-port <num>             自定义规则：源端口（可选）\n"
            << "  --rule-dst-port <num>             自定义规则：目的端口（可选）\n"
            << "  --rule-max-traffic                自定义规则：最大流量阈值（可选）\n"
            << "  --help                            显示此帮助\n";
}

// 主函数，解析命令行参数并执行相应的任务
int main(int argc, char *argv[]) {
# ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8); // 设置控制台输出为 UTF-8
# endif

    try {
        string inputFile, task, targetIP, srcIP, dstIP, outputJsonFile;
        string ruleTarget, rangeCIDR, rangeStart, rangeEnd, ruleTypeStr;
        string sortType = "total"; // 默认使用总流量排序
        double ratioThreshold = 0.8, inDataThreshold = 1LL << 30; // 默认出流量占比阈值和DDoS入流量阈值
        uint8_t ruleProtocol = 0;
        uint16_t ruleSrcPort = 0, ruleDstPort = 0;
        long long maxTraffic = (numeric_limits<long long>::max)();
        bool hasCIDR = false, hasStartEnd = false;
        int threshold = 0;
        const int cpuCount = static_cast<int>(thread::hardware_concurrency());
        int threads = cpuCount >= 4 ? 4 : cpuCount; //默认线程数为4

        // 解析参数
        for (int i = 1; i < argc; ++i) {
            const string arg = argv[i];
            if (arg == "--input" && i + 1 < argc) {
                inputFile = argv[++i];
            } else if (arg == "--task" && i + 1 < argc) {
                task = argv[++i];
            } else if (arg == "--target" && i + 1 < argc) {
                targetIP = argv[++i];
            } else if (arg == "--src" && i + 1 < argc) {
                srcIP = argv[++i];
            } else if (arg == "--dst" && i + 1 < argc) {
                dstIP = argv[++i];
            } else if (arg == "--threshold" && i + 1 < argc) {
                threshold = stoi(argv[++i]);
            } else if (arg == "--threads" && i + 1 < argc) {
                threads = stoi(argv[++i]);
                if (threads < 1) threads = 1;
            } else if (arg == "--output-json" && i + 1 < argc) {
                outputJsonFile = argv[++i];
            } else if (arg == "--sort-type" && i + 1 < argc) {
                sortType = argv[++i];
            } else if (arg == "--ratio-threshold" && i + 1 < argc) {
                ratioThreshold = stod(argv[++i]);
            } else if (arg == "--in-data-threshold" && i + 1 < argc) {
                inDataThreshold = stoll(argv[++i]);
            } else if (arg == "--help") {
                printUsage(argv[0]);
                return 0;
            } else if (arg == "--rule-target" && i + 1 < argc) {
                ruleTarget = argv[++i];
            } else if (arg == "--range-cidr" && i + 1 < argc) {
                rangeCIDR = argv[++i];
                hasCIDR = true;
            } else if (arg == "--range-start" && i + 1 < argc) {
                rangeStart = argv[++i];
                hasStartEnd = true;
            } else if (arg == "--range-end" && i + 1 < argc) {
                rangeEnd = argv[++i];
            } else if (arg == "--rule-type" && i + 1 < argc) {
                ruleTypeStr = argv[++i];
            } else if (arg == "--rule-protocol" && i + 1 < argc) {
                ruleProtocol = static_cast<uint8_t>(stoi(argv[++i]));
            } else if (arg == "--rule-src-port" && i + 1 < argc) {
                ruleSrcPort = static_cast<uint16_t>(stoi(argv[++i]));
            } else if (arg == "--rule-dst-port" && i + 1 < argc) {
                ruleDstPort = static_cast<uint16_t>(stoi(argv[++i]));
            } else if (arg == "--rule-max-traffic" && i + 1 < argc) {
                maxTraffic = stoll(argv[++i]);
            } else {
                cerr << "未知选项或缺少参数: " << argv[i] << "\n";
                printUsage(argv[0]);
                return 1;
            }
        }

        // 验证必要参数
        if (inputFile.empty() || task.empty()) {
            cerr << "错误: 必须指定 --input 和 --task\n";
            printUsage(argv[0]);
            return 1;
        }


        // 读取数据构建图
        CSVReader reader(inputFile, threads);
        Graph graph = reader.readCSV();

        // 任务分发
        if (task == "full-graph") {
            if (outputJsonFile.empty()) {
                cerr << "错误: full-graph 任务需要 --output-json\n";
                return 1;
            }

            SubgraphExporter(graph).exportFullGraph(outputJsonFile);
            cout << "全网拓扑已导出到 " << outputJsonFile << endl;
        } else if (task == "subgraph") {
            if (targetIP.empty() || outputJsonFile.empty()) {
                cerr << "错误: subgraph 任务需要 --target 和 --output-json\n";
                return 1;
            }
            SubgraphExporter(graph).exportSubGraph(IPAddress(targetIP.c_str()), outputJsonFile);
            cout << "子图已导出到 " << outputJsonFile << endl;
        } else if (task == "flow-sort") {
            if (sortType == "total") {
                auto sorted = graph.getNodesSortedByTotalTraffic();
                cout << "节点总流量排序 (IP, 总流量):\n";
                for (const auto &[ip, traffic]: sorted) {
                    cout << ip.toString() << "," << traffic << "\n";
                }
            } else if (sortType == "https") {
                auto sorted = graph.getNodesWithHTTPSortedByTraffic();
                cout << "HTTPS节点流量排序 (IP, HTTPS流量):\n";
                for (const auto &[ip, traffic]: sorted) {
                    cout << ip.toString() << "," << traffic << "\n";
                }
            } else if (sortType == "outratio") {
                auto sorted = graph.getNodesWithOutRatioAbove(ratioThreshold);
                cout << "出流量占比 >= " << ratioThreshold << " 的节点排序 (IP, 总流量, 出流量占比):\n";
                for (const auto &[ip, total, ratio]: sorted) {
                    cout << ip.toString() << "," << total << "," << ratio << "\n";
                }
            } else {
                cerr << "错误: 未知的排序类型 '" << sortType << "', 可选: total, https, outratio\n";
                return 1;
            }
        } else if (task == "min-congestion") {
            if (srcIP.empty() || dstIP.empty()) {
                cerr << "错误: min-congestion 需要 --src 和 --dst\n";
                return 1;
            }
            auto paths = graph.minCongestion(IPAddress(srcIP.c_str()), IPAddress(dstIP.c_str()));
            cout << "最小拥塞路径 (共 " << paths.size() << " 条):\n";
            if (paths.empty()) {
                cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
            } else {
                for (const auto &[path, congestion]: paths) {
                    for (int idx: path)
                        cout << graph.getVertexIP(idx).toString() << " ";
                    cout << "| congestion=" << congestion << "\n";
                }
            }
            if (!outputJsonFile.empty()) {
                SubgraphExporter(graph).exportPathsAsSubgraph(paths, outputJsonFile);
                cout << "路径子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "min-hop") {
            if (srcIP.empty() || dstIP.empty()) {
                cerr << "错误: min-hop 需要 --src 和 --dst\n";
                return 1;
            }
            int minHopCount;
            auto paths = graph.minHop(IPAddress(srcIP.c_str()), IPAddress(dstIP.c_str()), minHopCount);
            cout << "最小跳数路径 (最小跳数 = " << minHopCount << "):\n";
            if (paths.empty()) {
                cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
            } else {
                for (const auto &[path, congestion]: paths) {
                    for (int idx: path)
                        cout << graph.getVertexIP(idx).toString() << " ";
                    cout << "| congestion=" << congestion << "\n";
                }
            }
            if (!outputJsonFile.empty()) {
                SubgraphExporter(graph).exportPathsAsSubgraph(paths, outputJsonFile);
                cout << "路径子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "min-risk") {
            if (srcIP.empty() || dstIP.empty()) {
                cerr << "错误: min-risk 需要 --src 和 --dst\n";
                return 1;
            }
            double minRiskLevel;
            auto paths = graph.minCostCustom(IPAddress(srcIP.c_str()), IPAddress(dstIP.c_str()), minRiskLevel);
            cout << "最小风险路径 (最小风险值 = " << minRiskLevel << "):\n";
            if (paths.empty()) {
                cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
            } else {
                for (const auto &[path, congestion]: paths) {
                    for (int idx: path)
                        cout << graph.getVertexIP(idx).toString() << " ";
                    cout << "| congestion=" << congestion << "\n";
                }
            }
            if (!outputJsonFile.empty()) {
                SubgraphExporter(graph).exportPathsAsSubgraph(paths, outputJsonFile);
                cout << "路径子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "compare-paths") {
            if (srcIP.empty() || dstIP.empty()) {
                cerr << "错误: compare-paths 需要 --src 和 --dst\n";
                return 1;
            }

            const IPAddress src(srcIP.c_str()), dst(dstIP.c_str());

            // 分别获取三种路径
            // 最小拥塞路径
            auto pathsCong = graph.minCongestion(src, dst);
            cout << "最小拥塞路径 (共 " << pathsCong.size() << " 条):\n";
            if (pathsCong.empty()) {
                cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
            } else {
                for (const auto &[path, congestion]: pathsCong) {
                    for (int idx: path)
                        cout << graph.getVertexIP(idx).toString() << " ";
                    cout << "| congestion=" << congestion << "\n";
                }
            }

            // 最小跳数路径
            int minHopCount;
            auto pathsHop = graph.minHop(IPAddress(srcIP.c_str()), IPAddress(dstIP.c_str()), minHopCount);
            cout << "最小跳数路径 (最小跳数 = " << minHopCount << "):\n";
            if (pathsHop.empty()) {
                cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
            } else {
                for (const auto &[path, congestion]: pathsHop) {
                    for (int idx: path)
                        cout << graph.getVertexIP(idx).toString() << " ";
                    cout << "| congestion=" << congestion << "\n";
                }
            }

            // 最小风险路径
            double minRiskLevel;
            auto pathsRisk = graph.minCostCustom(IPAddress(srcIP.c_str()), IPAddress(dstIP.c_str()), minRiskLevel);
            cout << "最小风险路径 (最小风险值 = " << minRiskLevel << "):\n";
            if (pathsRisk.empty()) {
                cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
            } else {
                for (const auto &[path, congestion]: pathsRisk) {
                    for (int idx: path)
                        cout << graph.getVertexIP(idx).toString() << " ";
                    cout << "| congestion=" << congestion << "\n";
                }
            }

            // 导出合并子图
            if (!outputJsonFile.empty()) {
                vector pathsList = {pathsCong, pathsHop, pathsRisk};
                SubgraphExporter(graph).exportPathsAsSubgraph(pathsList, outputJsonFile);
                cout << "对比路径子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "port-scan") {
            int thr = threshold > 0 ? threshold : 20;
            auto scanners = graph.detectPortScanners(thr, ratioThreshold);
            cout << "检测到端口扫描攻击者 (" << scanners.size() << " 个):\n";
            for (const auto &[ip, portCount, outRatio]: scanners) {
                cout << ip.toString() << "," << portCount << "," << outRatio << "\n";
            }
            if (!outputJsonFile.empty()) {
                SubgraphExporter(graph).exportPortScannersAsSubgraph(scanners, outputJsonFile);
                cout << "端口扫描攻击者子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "ddos-target") {
            int thr = threshold > 0 ? threshold : 20;
            auto targets = graph.detectDDoSTargets(thr, inDataThreshold);
            cout << "检测到DDoS攻击目标 (" << targets.size() << " 个):\n";
            for (const auto &[ip, neighborCount, inData]: targets) {
                cout << ip.toString() << "," << neighborCount << "," << inData << "\n";
            }
            if (!outputJsonFile.empty()) {
                SubgraphExporter(graph).exportDDoSTargetsAsSubgraph(targets, outputJsonFile);
                cout << "DDoS攻击目标子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "star-structures") {
            int thr = threshold > 0 ? threshold : 20;
            auto stars = graph.findStarStructures(thr);
            cout << "找到星型结构 (" << stars.size() << " 个):\n";
            for (size_t i = 0; i < stars.size(); ++i) {
                const auto &[center, neighbors, totalData] = stars[i];
                cout << "星型 " << i + 1 << ": 中心=" << center.toString()
                        << ", 邻居数=" << neighbors.size()
                        << ", 总流量=" << totalData << "\n";
                cout << "  邻居 (IP, 流量): ";
                for (const auto &[ip, traffic]: neighbors) {
                    cout << ip.toString() << "(" << traffic << ") ";
                }
                cout << "\n";
            }
            if (!outputJsonFile.empty()) {
                SubgraphExporter(graph).exportStarStructureAsSubgraph(stars, outputJsonFile);
                cout << "星型结构子图已导出到 " << outputJsonFile << endl;
            }
        } else if (task == "custom-rule") {
            // 验证必要参数
            if (ruleTarget.empty()) {
                cerr << "错误: custom-rule 需要 --rule-src\n";
                return 1;
            }
            if (!hasCIDR && !(hasStartEnd && !rangeStart.empty() && !rangeEnd.empty())) {
                cerr << "错误: 必须指定 IP 范围，使用 --range-cidr 或 --range-start/--range-end\n";
                return 1;
            }
            if (hasCIDR && hasStartEnd) {
                cerr << "警告: 同时提供了 CIDR 和起止IP，将优先使用 CIDR\n";
            }

            auto type = RuleType::DENY;
            if (!ruleTypeStr.empty()) {
                if (ruleTypeStr == "allow") type = RuleType::ALLOW;
                else if (ruleTypeStr == "deny") type = RuleType::DENY;
                else {
                    cerr << "无效的规则类型: " << ruleTypeStr << "\n";
                    return 1;
                }
            }

            try {
                unique_ptr<CustomRule> rule;
                if (hasCIDR) {
                    rule = make_unique<CustomRule>(graph, IPAddress(ruleTarget.c_str()), rangeCIDR,
                                                   ruleProtocol, ruleSrcPort, ruleDstPort, type, maxTraffic);
                } else {
                    rule = make_unique<CustomRule>(graph, IPAddress(ruleTarget.c_str()),
                                                   IPAddress(rangeStart.c_str()), IPAddress(rangeEnd.c_str()),
                                                   ruleProtocol, ruleSrcPort, ruleDstPort, type, maxTraffic);
                }

                auto violations = rule->ViolationRecords();
                cout << "违反规则的通信记录 (" << violations.size() << " 条):\n";
                if (violations.empty()) {
                    cout << "  无违规记录\n";
                } else {
                    for (const auto &v: violations) {
                        cout << "  " << v.getSrcIP().toString() << " -> " << v.getDstIP().toString()
                                << " [proto=" << static_cast<int>(v.getProtocol())
                                << ", srcPort=" << v.getSrcPort() << ", dstPort=" << v.getDstPort()
                                << "] reason: " << v.getReason() << "\n";
                    }
                }

                if (!outputJsonFile.empty()) {
                    SubgraphExporter(graph).exportViolationsAsSubgraph(IPAddress(ruleTarget.c_str()), violations,
                                                                       outputJsonFile);
                    cout << "违规通信子图已导出到 " << outputJsonFile << endl;
                }
            } catch (const exception &e) {
                cerr << "custom-rule 执行失败: " << e.what() << endl;
                return 1;
            }
        } else {
            cerr << "未知任务: " << task << "\n";
            printUsage(argv[0]);
            return 1;
        }

        return 0;
    } catch (const exception &e) {
        cerr << "错误: " << e.what() << endl;
        return 1;
    }
}
