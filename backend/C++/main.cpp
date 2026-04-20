// main.cpp

# ifdef _WIN32
#  ifndef NOMINMAX
#   define NOMINMAX
#  endif
#  include <windows.h>
# endif
# include "Graph.h"
# include "CSVReader.h"
# include "CustomRule.h"
# include "SubgraphExporter.h"
# include <iostream>
# include <limits>
# include <optional>
# include <string>
# include <thread>    // for hardware_concurrency
# include <memory>

using namespace std;

void printUsage(const char *progName);

namespace {
    struct ParsedArgs {
        string inputFile;
        string task;
        string targetIP;
        string srcIP;
        string dstIP;
        string outputJsonFile;
        string ruleTarget;
        string rangeCIDR;
        string rangeStart;
        string rangeEnd;
        string ruleTypeStr;
        string sortType = "total";
        double ratioThreshold = 0.8;
        double inRatioThreshold = 0.8;
        uint8_t ruleProtocol = 0;
        uint16_t ruleSrcPort = 0;
        uint16_t ruleDstPort = 0;
        long long maxTraffic = (numeric_limits<long long>::max)();
        long long inDataThreshold = 1LL << 30;
        long long minTraffic = 0;
        bool hasCIDR = false;
        bool hasStartEnd = false;
        int threshold = 0;
        int threads = static_cast<int>(Graph::defaultThreadCount());
        size_t maxPaths = DEFAULT_MAX_PATHS;
        optional<IPAddress> targetAddress;
        optional<IPAddress> srcAddress;
        optional<IPAddress> dstAddress;
        optional<IPAddress> ruleTargetAddress;
        optional<IPAddress> rangeStartAddress;
        optional<IPAddress> rangeEndAddress;
    };

    long long parseLongLongOption(const string &option, const string &value, const long long minValue,
                                  const long long maxValue) {
        size_t pos = 0;
        long long parsed = 0;
        try {
            parsed = stoll(value, &pos);
        } catch (const exception &) {
            throw invalid_argument(option + " 必须为整数: " + value);
        }
        if (pos != value.size()) {
            throw invalid_argument(option + " 包含非法字符: " + value);
        }
        if (parsed < minValue || parsed > maxValue) {
            throw out_of_range(option + " 超出范围: " + value);
        }
        return parsed;
    }

    int parseIntOption(const string &option, const string &value, const int minValue, const int maxValue) {
        return static_cast<int>(parseLongLongOption(option, value, minValue, maxValue));
    }

    size_t parseSizeOption(const string &option, const string &value, const size_t minValue) {
        size_t pos = 0;
        unsigned long long parsed = 0;
        try {
            parsed = stoull(value, &pos);
        } catch (const exception &) {
            throw invalid_argument(option + " 必须为正整数: " + value);
        }
        if (pos != value.size()) {
            throw invalid_argument(option + " 包含非法字符: " + value);
        }
        if (parsed < minValue) {
            throw out_of_range(option + " 不能小于 " + to_string(minValue) + ": " + value);
        }
        return parsed;
    }

    double parseDoubleOption(const string &option, const string &value, const double minValue,
                             const double maxValue) {
        size_t pos = 0;
        double parsed = 0;
        try {
            parsed = stod(value, &pos);
        } catch (const exception &) {
            throw invalid_argument(option + " 必须为数字: " + value);
        }
        if (pos != value.size()) {
            throw invalid_argument(option + " 包含非法字符: " + value);
        }
        if (parsed < minValue || parsed > maxValue) {
            throw out_of_range(option + " 超出范围: " + value);
        }
        return parsed;
    }

    IPAddress parseIPOption(const string &option, const string &value) {
        if (value.empty()) {
            throw invalid_argument(option + " 不能为空");
        }
        return IPAddress(value);
    }

    void validateCIDROption(const string &value) {
        const size_t slashPos = value.find('/');
        if (slashPos == string::npos) {
            throw invalid_argument("--range-cidr 格式错误: " + value);
        }
        const string ipPart = value.substr(0, slashPos);
        const string maskPart = value.substr(slashPos + 1);
        parseIPOption("--range-cidr", ipPart);
        parseIntOption("--range-cidr 掩码长度", maskPart, 0, 32);
    }

    bool isPathTask(const string &task) {
        return task == "min-congestion" || task == "min-hop" || task == "min-risk";
    }

    bool isKnownTask(const string &task) {
        return task == "full-graph" || task == "subgraph" || task == "flow-sort" || isPathTask(task) ||
               task == "compare-paths" || task == "port-scan" || task == "ddos-target" ||
               task == "star-structures" || task == "custom-rule";
    }

    void printNoPathFound(const string &srcIP, const string &dstIP) {
        cout << "没有找到从 " << srcIP << " 到 " << dstIP << " 的路径\n";
    }

    void printPathInfoList(const Graph &graph, const vector<PathInfo> &paths, const string &metricName) {
        for (const auto &[path, metricValue]: paths) {
            for (const int idx: path) {
                cout << graph.getVertexIP(idx).toString() << " ";
            }
            cout << "| " << metricName << "=" << metricValue << "\n";
        }
    }

    void printSinglePathTaskResult(const Graph &graph, const vector<PathInfo> &paths, const string &title,
                                   const string &metricName, const string &srcIP, const string &dstIP) {
        cout << title << "\n";
        if (paths.empty()) {
            printNoPathFound(srcIP, dstIP);
            return;
        }
        printPathInfoList(graph, paths, metricName);
    }

    void exportPathsIfRequested(const Graph &graph, const vector<PathInfo> &paths, const string &outputJsonFile,
                                const string &successMessage) {
        if (outputJsonFile.empty()) {
            return;
        }
        SubgraphExporter(graph).exportPathsAsSubgraph(paths, outputJsonFile);
        cout << successMessage << " " << outputJsonFile << endl;
    }

    void exportComparedPathsIfRequested(const Graph &graph, const vector<vector<PathInfo> > &pathsList,
                                        const string &outputJsonFile) {
        if (outputJsonFile.empty()) {
            return;
        }
        SubgraphExporter(graph).exportPathsAsSubgraph(pathsList, outputJsonFile);
        cout << "对比路径子图已导出到 " << outputJsonFile << endl;
    }

    ParsedArgs parseArguments(const int argc, char *argv[]) {
        ParsedArgs args = {};
        for (int i = 1; i < argc; ++i) {
            const string arg = argv[i];
            if (arg == "--input" && i + 1 < argc) {
                args.inputFile = argv[++i];
            } else if (arg == "--task" && i + 1 < argc) {
                args.task = argv[++i];
            } else if (arg == "--target" && i + 1 < argc) {
                args.targetIP = argv[++i];
            } else if (arg == "--src" && i + 1 < argc) {
                args.srcIP = argv[++i];
            } else if (arg == "--dst" && i + 1 < argc) {
                args.dstIP = argv[++i];
            } else if (arg == "--threshold" && i + 1 < argc) {
                args.threshold = parseIntOption("--threshold", argv[++i], 0, (numeric_limits<int>::max)());
            } else if (arg == "--threads" && i + 1 < argc) {
                args.threads = parseIntOption("--threads", argv[++i], 1, (numeric_limits<int>::max)());
            } else if (arg == "--max-paths" && i + 1 < argc) {
                args.maxPaths = parseSizeOption("--max-paths", argv[++i], 1);
            } else if (arg == "--output-json" && i + 1 < argc) {
                args.outputJsonFile = argv[++i];
            } else if (arg == "--sort-type" && i + 1 < argc) {
                args.sortType = argv[++i];
            } else if (arg == "--ratio-threshold" && i + 1 < argc) {
                args.ratioThreshold = parseDoubleOption("--ratio-threshold", argv[++i], 0.0, 1.0);
            } else if (arg == "--in-data-threshold" && i + 1 < argc) {
                args.inDataThreshold = parseLongLongOption("--in-data-threshold", argv[++i], 0,
                                                           (numeric_limits<long long>::max)());
            } else if (arg == "--in-ratio-threshold" && i + 1 < argc) {
                args.inRatioThreshold = parseDoubleOption("--in-ratio-threshold", argv[++i], 0.0, 1.0);
            } else if (arg == "--min-traffic" && i + 1 < argc) {
                args.minTraffic = parseLongLongOption("--min-traffic", argv[++i], 0,
                                                      (numeric_limits<long long>::max)());
            } else if (arg == "--help") {
                printUsage(argv[0]);
                exit(0);
            } else if (arg == "--rule-target" && i + 1 < argc) {
                args.ruleTarget = argv[++i];
            } else if (arg == "--range-cidr" && i + 1 < argc) {
                args.rangeCIDR = argv[++i];
                args.hasCIDR = true;
            } else if (arg == "--range-start" && i + 1 < argc) {
                args.rangeStart = argv[++i];
                args.hasStartEnd = true;
            } else if (arg == "--range-end" && i + 1 < argc) {
                args.rangeEnd = argv[++i];
            } else if (arg == "--rule-type" && i + 1 < argc) {
                args.ruleTypeStr = argv[++i];
            } else if (arg == "--rule-protocol" && i + 1 < argc) {
                args.ruleProtocol = static_cast<uint8_t>(parseIntOption("--rule-protocol", argv[++i], 0, 255));
            } else if (arg == "--rule-src-port" && i + 1 < argc) {
                args.ruleSrcPort = static_cast<uint16_t>(parseIntOption("--rule-src-port", argv[++i], 0, 65535));
            } else if (arg == "--rule-dst-port" && i + 1 < argc) {
                args.ruleDstPort = static_cast<uint16_t>(parseIntOption("--rule-dst-port", argv[++i], 0, 65535));
            } else if (arg == "--rule-max-traffic" && i + 1 < argc) {
                args.maxTraffic = parseLongLongOption("--rule-max-traffic", argv[++i], 0,
                                                      (numeric_limits<long long>::max)());
            } else {
                throw invalid_argument("未知选项或缺少参数: " + arg);
            }
        }
        return args;
    }

    void validateArguments(ParsedArgs &args) {
        if (args.inputFile.empty() || args.task.empty()) {
            throw invalid_argument("必须指定 --input 和 --task");
        }
        if (!isKnownTask(args.task)) {
            throw invalid_argument("未知任务: " + args.task);
        }
        if (args.task == "full-graph" && args.outputJsonFile.empty()) {
            throw invalid_argument("full-graph 任务需要 --output-json");
        }
        if (args.task == "subgraph") {
            if (args.targetIP.empty() || args.outputJsonFile.empty()) {
                throw invalid_argument("subgraph 任务需要 --target 和 --output-json");
            }
            args.targetAddress = parseIPOption("--target", args.targetIP);
        }
        if (isPathTask(args.task) || args.task == "compare-paths") {
            if (args.srcIP.empty() || args.dstIP.empty()) {
                throw invalid_argument(args.task + " 需要 --src 和 --dst");
            }
            args.srcAddress = parseIPOption("--src", args.srcIP);
            args.dstAddress = parseIPOption("--dst", args.dstIP);
        }
        if (args.task == "flow-sort" && args.sortType != "total" && args.sortType != "https" &&
            args.sortType != "outratio") {
            throw invalid_argument("未知的排序类型 '" + args.sortType + "', 可选: total, https, outratio");
        }
        if (args.task != "custom-rule") {
            return;
        }

        if (args.ruleTarget.empty()) {
            throw invalid_argument("custom-rule 需要 --rule-target");
        }
        args.ruleTargetAddress = parseIPOption("--rule-target", args.ruleTarget);
        if (!args.hasCIDR && !(args.hasStartEnd && !args.rangeStart.empty() && !args.rangeEnd.empty())) {
            throw invalid_argument("必须指定 IP 范围，使用 --range-cidr 或 --range-start/--range-end");
        }
        if (args.hasCIDR) {
            validateCIDROption(args.rangeCIDR);
        }
        if (args.hasStartEnd) {
            if (args.rangeStart.empty() || args.rangeEnd.empty()) {
                throw invalid_argument("--range-start 需要与 --range-end 配合使用");
            }
            args.rangeStartAddress = parseIPOption("--range-start", args.rangeStart);
            args.rangeEndAddress = parseIPOption("--range-end", args.rangeEnd);
            if (args.rangeStartAddress->getIP() > args.rangeEndAddress->getIP()) {
                throw invalid_argument("起始IP不能大于结束IP");
            }
        }
        if (!args.ruleTypeStr.empty() && args.ruleTypeStr != "allow" && args.ruleTypeStr != "deny") {
            throw invalid_argument("无效的规则类型: " + args.ruleTypeStr);
        }
    }

    void runFlowSortTask(const Graph &graph, const ParsedArgs &args) {
        if (args.sortType == "total") {
            const auto sorted = graph.getNodesSortedByTotalTraffic();
            cout << "节点总流量排序 (IP, 总流量):\n";
            for (const auto &[ip, traffic]: sorted) {
                cout << ip.toString() << "," << traffic << "\n";
            }
            return;
        }
        if (args.sortType == "https") {
            const auto sorted = graph.getNodesWithHTTPSortedByTraffic();
            cout << "HTTPS节点流量排序 (IP, HTTPS流量):\n";
            for (const auto &[ip, traffic]: sorted) {
                cout << ip.toString() << "," << traffic << "\n";
            }
            return;
        }
        const auto sorted = graph.getNodesWithOutRatioAbove(args.ratioThreshold);
        cout << "出流量占比 >= " << args.ratioThreshold << " 的节点排序 (IP, 总流量, 出流量占比):\n";
        for (const auto &[ip, total, ratio]: sorted) {
            cout << ip.toString() << "," << total << "," << ratio << "\n";
        }
    }

    void runSinglePathTask(const Graph &graph, const ParsedArgs &args) {
        if (args.task == "min-congestion") {
            const auto paths = graph.minCongestion(*args.srcAddress, *args.dstAddress, args.maxPaths);
            printSinglePathTaskResult(
                graph, paths, "最小拥塞路径 (共 " + to_string(paths.size()) + " 条):", "congestion", args.srcIP,
                args.dstIP
            );
            exportPathsIfRequested(graph, paths, args.outputJsonFile, "路径子图已导出到");
            return;
        }
        if (args.task == "min-hop") {
            int minHopCount = 0;
            const auto paths = graph.minHop(*args.srcAddress, *args.dstAddress, minHopCount, args.maxPaths);
            printSinglePathTaskResult(
                graph, paths, "最小跳数路径 (最小跳数 = " + to_string(minHopCount) + "):", "congestion", args.srcIP,
                args.dstIP
            );
            exportPathsIfRequested(graph, paths, args.outputJsonFile, "路径子图已导出到");
            return;
        }

        double minRiskLevel = 0;
        const auto paths = graph.minCostCustom(*args.srcAddress, *args.dstAddress, minRiskLevel, args.maxPaths);
        printSinglePathTaskResult(
            graph, paths, "最小风险路径 (最小风险值 = " + to_string(minRiskLevel) + "):", "risk", args.srcIP,
            args.dstIP
        );
        exportPathsIfRequested(graph, paths, args.outputJsonFile, "路径子图已导出到");
    }

    void runComparePathsTask(const Graph &graph, const ParsedArgs &args) {
        const auto pathsCong = graph.minCongestion(*args.srcAddress, *args.dstAddress, args.maxPaths);
        printSinglePathTaskResult(
            graph, pathsCong, "最小拥塞路径 (共 " + to_string(pathsCong.size()) + " 条):", "congestion", args.srcIP,
            args.dstIP
        );

        int minHopCount = 0;
        const auto pathsHop = graph.minHop(*args.srcAddress, *args.dstAddress, minHopCount, args.maxPaths);
        printSinglePathTaskResult(
            graph, pathsHop, "最小跳数路径 (最小跳数 = " + to_string(minHopCount) + "):", "congestion", args.srcIP,
            args.dstIP
        );

        double minRiskLevel = 0;
        const auto pathsRisk = graph.minCostCustom(*args.srcAddress, *args.dstAddress, minRiskLevel, args.maxPaths);
        printSinglePathTaskResult(
            graph, pathsRisk, "最小风险路径 (最小风险值 = " + to_string(minRiskLevel) + "):", "risk", args.srcIP,
            args.dstIP
        );

        exportComparedPathsIfRequested(graph, {pathsCong, pathsHop, pathsRisk}, args.outputJsonFile);
    }

    void runPortScanTask(const Graph &graph, const ParsedArgs &args) {
        const int thr = args.threshold > 0 ? args.threshold : 20;
        const auto scanners = graph.detectPortScanners(thr, args.ratioThreshold, args.minTraffic);
        cout << "检测到端口扫描攻击者 (" << scanners.size() << " 个):\n";
        for (const auto &scanner: scanners) {
            cout << scanner.ip.toString() << ","
                    << scanner.portCount << ","
                    << scanner.targetCount << ","
                    << scanner.scanType << ","
                    << scanner.outRatio << ","
                    << scanner.totalTraffic << "\n";
        }
        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).exportPortScannersAsSubgraph(scanners, args.outputJsonFile);
            cout << "端口扫描攻击者子图已导出到 " << args.outputJsonFile << endl;
        }
    }

    void runDDoSTask(const Graph &graph, const ParsedArgs &args) {
        const int thr = args.threshold > 0 ? args.threshold : 20;
        const auto targets = graph.detectDDoSTargets(thr, args.inDataThreshold, args.inRatioThreshold);
        cout << "检测到DDoS攻击目标 (" << targets.size() << " 个):\n";
        for (const auto &target: targets) {
            cout << target.ip.toString() << ","
                    << target.sourceCount << ","
                    << target.inData << ","
                    << target.inRatio << "\n";
        }
        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).exportDDoSTargetsAsSubgraph(targets, args.outputJsonFile);
            cout << "DDoS攻击目标子图已导出到 " << args.outputJsonFile << endl;
        }
    }

    void runStarTask(const Graph &graph, const ParsedArgs &args) {
        const int thr = args.threshold > 0 ? args.threshold : 20;
        const auto stars = graph.findStarStructures(thr);
        cout << "找到星型结构 (" << stars.size() << " 个):\n";
        for (size_t i = 0; i < stars.size(); ++i) {
            const auto &[center, neighbors, totalData, inData, outData, leafRatio] = stars[i];
            cout << "星型 " << i + 1 << ": 中心=" << center.toString()
                    << ", 邻居数=" << neighbors.size()
                    << ", 总流量=" << totalData
                    << ", 入流量=" << inData
                    << ", 出流量=" << outData
                    << ", 叶子占比=" << leafRatio << "\n";
            cout << "  邻居 (IP, 流量): ";
            for (const auto &[ip, traffic]: neighbors) {
                cout << ip.toString() << "(" << traffic << ") ";
            }
            cout << "\n";
        }
        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).exportStarStructureAsSubgraph(stars, args.outputJsonFile);
            cout << "星型结构子图已导出到 " << args.outputJsonFile << endl;
        }
    }

    void runCustomRuleTask(const Graph &graph, const ParsedArgs &args) {
        const auto type = args.ruleTypeStr == "allow" ? RuleType::ALLOW : RuleType::DENY;
        unique_ptr<CustomRule> rule;
        if (args.hasCIDR) {
            rule = make_unique<CustomRule>(
                graph, *args.ruleTargetAddress, args.rangeCIDR, args.ruleProtocol, args.ruleSrcPort,
                args.ruleDstPort, type, args.maxTraffic
            );
        } else {
            rule = make_unique<CustomRule>(
                graph, *args.ruleTargetAddress, *args.rangeStartAddress, *args.rangeEndAddress, args.ruleProtocol,
                args.ruleSrcPort, args.ruleDstPort, type, args.maxTraffic
            );
        }

        const auto violations = rule->ViolationRecords();
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

        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).
                    exportViolationsAsSubgraph(*args.ruleTargetAddress, violations, args.outputJsonFile);
            cout << "违规通信子图已导出到 " << args.outputJsonFile << endl;
        }
    }

    void runTask(const Graph &graph, const ParsedArgs &args) {
        if (args.task == "full-graph") {
            SubgraphExporter(graph).exportFullGraph(args.outputJsonFile);
            cout << "全网拓扑已导出到 " << args.outputJsonFile << endl;
            return;
        }
        if (args.task == "subgraph") {
            SubgraphExporter(graph).exportSubGraph(*args.targetAddress, args.outputJsonFile);
            cout << "子图已导出到 " << args.outputJsonFile << endl;
            return;
        }
        if (args.task == "flow-sort") {
            runFlowSortTask(graph, args);
            return;
        }
        if (isPathTask(args.task)) {
            runSinglePathTask(graph, args);
            return;
        }
        if (args.task == "compare-paths") {
            runComparePathsTask(graph, args);
            return;
        }
        if (args.task == "port-scan") {
            runPortScanTask(graph, args);
            return;
        }
        if (args.task == "ddos-target") {
            runDDoSTask(graph, args);
            return;
        }
        if (args.task == "star-structures") {
            runStarTask(graph, args);
            return;
        }
        runCustomRuleTask(graph, args);
    }
}

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
            << "  --in-ratio-threshold <num>        入流量占比阈值（DDoS，0-1）\n"
            << "  --min-traffic <num>               最小总流量阈值（端口扫描）\n"
            << "  --threads <num>                   线程数（默认CPU核心数）\n"
            << "  --max-paths <num>                 最多输出的等价路径数量（默认100）\n"
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
        ParsedArgs args = parseArguments(argc, argv);
        validateArguments(args);
        if (args.hasCIDR && args.hasStartEnd) {
            cerr << "警告: 同时提供了 CIDR 和起止IP，将优先使用 CIDR\n";
        }

        // 读取数据构建图
        CSVReader reader(args.inputFile, args.threads);
        const Graph graph = reader.readCSV();
        runTask(graph, args);
        return 0;
    } catch (const exception &e) {
        cerr << "错误: " << e.what() << endl;
        return 1;
    }
}
