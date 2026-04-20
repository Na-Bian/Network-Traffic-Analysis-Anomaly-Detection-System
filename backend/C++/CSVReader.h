//
// Created by Na_Bian on 2026/3/3.
//

# ifndef NETWORKANALYZER_CSV_READER_H
# define NETWORKANALYZER_CSV_READER_H

# include "Graph.h"

# include <fstream>
# include <unordered_set>
# include <iostream>
# include <utility>
# include <limits>
# include <algorithm>
# include <cctype>
# include <future>
# include <sstream>


class CSVReader {
    std::string CSVFile; // CSV文件名
    unsigned int totalLines = 0; // CSV文件的总行数
    unsigned int numThreads = 1; //用于读取和处理CSV文件的线程数量

    struct Record {
        IPAddress srcIP;
        IPAddress dstIP;
        uint8_t protocol;
        uint16_t srcPort;
        uint16_t dstPort;
        int dataSize;
        double duration;
    };

    // 辅助函数trim用于去除字符串首尾的空白字符
    static std::string trim(const std::string &value) {
        const auto begin = std::ranges::find_if_not(value, [](const unsigned char ch) {
            return std::isspace(ch) != 0;
        });
        // 用反向迭代器从字符串尾部逆向查找第一个非空白字符的位置
        const auto end = std::find_if_not(value.rbegin(), value.rend(), [](const unsigned char ch) {
            return std::isspace(ch) != 0;
        }).base(); //转换为正向迭代器
        return begin < end ? std::string(begin, end) : "";
    }

    static std::vector<std::string> splitCSVLine(const std::string &line) {
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, ',')) {
            fields.push_back(trim(field));
        }
        if (!line.empty() && line.back() == ',') fields.emplace_back();
        return fields;
    }

    static int parseIntInRange(const std::string &value, const int minValue, const int maxValue,
                               const std::string &fieldName) {
        size_t pos = 0;
        int parsed = 0;
        try {
            parsed = std::stoi(value, &pos);
        } catch (const std::exception &) {
            pos = 0;
            const double asDouble = std::stod(value, &pos);
            if (pos != value.size()) throw std::invalid_argument(fieldName + "包含非数字字符: " + value);
            if (std::floor(asDouble) != asDouble) {
                throw std::invalid_argument(fieldName + "必须为整数: " + value);
            }
            if (asDouble < static_cast<double>(minValue) || asDouble > static_cast<double>(maxValue)) {
                throw std::out_of_range(fieldName + "超出范围: " + value);
            }
            parsed = static_cast<int>(asDouble);
            return parsed;
        }
        if (pos != value.size()) {
            if (value.substr(pos) == ".0") return parsed;
            throw std::invalid_argument(fieldName + "包含非数字字符: " + value);
        }
        if (parsed < minValue || parsed > maxValue) {
            throw std::out_of_range(fieldName + "超出范围: " + value);
        }
        return parsed;
    }

    static double parseNonNegativeDouble(const std::string &value, const std::string &fieldName) {
        size_t pos = 0;
        const double parsed = std::stod(value, &pos);
        if (pos != value.size()) throw std::invalid_argument(fieldName + "包含非法字符: " + value);
        if (parsed < 0) throw std::out_of_range(fieldName + "不能为负数: " + value);
        return parsed;
    }

    static Record parseRecord(const std::string &line) {
        const auto fields = splitCSVLine(line);
        if (fields.size() != 7) {
            throw std::invalid_argument("字段数量应为7，实际为" + std::to_string(fields.size()));
        }
        if (fields[0].empty() || fields[1].empty() || fields[2].empty()) {
            throw std::invalid_argument("源IP、目的IP和协议字段不能为空");
        }

        const int protocol = parseIntInRange(fields[2], 0, 255, "协议号");
        const int srcPort = fields[3].empty() ? 0 : parseIntInRange(fields[3], 0, 65535, "源端口");
        const int dstPort = fields[4].empty() ? 0 : parseIntInRange(fields[4], 0, 65535, "目的端口");
        const int dataSize = fields[5].empty()
                                 ? 0
                                 : parseIntInRange(fields[5], 0, (std::numeric_limits<int>::max)(), "数据大小");
        const double duration = fields[6].empty() ? 0.0 : parseNonNegativeDouble(fields[6], "持续时间");

        return {
            IPAddress(fields[0]), IPAddress(fields[1]), static_cast<uint8_t>(protocol),
            static_cast<uint16_t>(srcPort), static_cast<uint16_t>(dstPort), dataSize, duration
        };
    }

public:
    //构造函数，接受CSV文件名
    explicit CSVReader(std::string fileName = "network_data.csv",
                       const unsigned int threads = Graph::defaultThreadCount())
        : CSVFile(std::move(fileName)), numThreads(threads) {
        std::ifstream fin(CSVFile, std::ios::binary | std::ios::ate); //以二进制模式打开CSV文件，并将文件指针移动到文件末尾
        if (threads < 1) throw std::invalid_argument("线程数量必须至少为1");
        if (!fin.is_open()) throw std::runtime_error("无法打开文件: " + CSVFile);
        fin.close();
    }

    //函数readCSV用于从CSV文件中读取网络数据，并将其构建为一个Graph对象
    //参数numThreads指定用于读取和处理CSV文件的线程数量，默认为当前计算机CPU的核心数
    [[nodiscard]] Graph readCSV(const Graph::ProgressCallback &progressCallback = {}) {
        std::unordered_set<uint32_t> uniqueIPs; // 存储唯一的IP地址
        std::ifstream fin(CSVFile);
        if (!fin.is_open()) throw std::runtime_error("无法打开文件: " + CSVFile);
        std::string line;
        std::getline(fin, line); // 跳过标题行
        unsigned int linesCount = 0; // 统计总行数
        std::vector<Record> records;
        if (progressCallback) progressCallback("进度: 开始解析 CSV 文件...");
        while (std::getline(fin, line)) {
            ++linesCount;
            try {
                const Record record = parseRecord(line);
                uniqueIPs.insert(record.srcIP.getIP());
                uniqueIPs.insert(record.dstIP.getIP());
                records.push_back(record);
            } catch (const std::exception &e) {
                std::cout << "数据行格式错误(第" << linesCount + 1 << "行): " << line
                        << " 错误信息: " << e.what() << std::endl;
            }
        }

        totalLines = linesCount; // 记录总行数，供后续分块处理使用

        fin.close();
        if (progressCallback) {
            progressCallback(
                "进度: CSV 解析完成，保留 " + std::to_string(records.size()) +
                " 条有效记录，识别 " + std::to_string(uniqueIPs.size()) + " 个唯一节点"
            );
        }

        // 构建Graph对象
        Graph graph;
        graph.reserve(uniqueIPs.size()); // 预先分配节点空间，减少后续添加节点时的重新分配次数

        std::vector<std::future<Graph> > futures; //存储线程的future对象

        const unsigned int workerCount = Graph::effectiveThreadCount(numThreads, records.size());
        if (progressCallback) {
            progressCallback(
                "进度: 使用 " + std::to_string(workerCount) + " 个线程并行构建局部图..."
            );
        }
        const unsigned int base = static_cast<unsigned int>(records.size()) / workerCount; //计算每个线程需要处理的记录数
        const unsigned int remainder = static_cast<unsigned int>(records.size()) % workerCount; //计算余数

        // 分块并行构建局部图，每个线程只处理自己的记录切片
        size_t begin = 0;
        for (unsigned int i = 0; i < workerCount; ++i) {
            const size_t recordsToRead = i < remainder ? base + 1 : base;
            if (recordsToRead == 0) continue;
            const size_t chunkBegin = begin;
            const size_t chunkEnd = chunkBegin + recordsToRead;
            begin = chunkEnd;
            futures.push_back(std::async(std::launch::async, [chunkBegin, chunkEnd, &records] {
                Graph localGraph;
                localGraph.reserve((chunkEnd - chunkBegin) * 2);
                for (size_t idx = chunkBegin; idx < chunkEnd; ++idx) {
                    const auto &[srcIP, dstIP, protocol, srcPort, dstPort, dataSize, duration] = records[idx];
                    localGraph.addRecord(
                        srcIP,
                        dstIP,
                        protocol,
                        srcPort,
                        dstPort,
                        dataSize,
                        duration
                    );
                }
                return localGraph;
            }));
        }

        for (auto &f: futures) {
            graph.mergeFrom(f.get());
        }

        if (progressCallback) progressCallback("进度: 图模型构建完成");

        return graph;
    }

    [[nodiscard]] unsigned int getTotalLines() const {
        return totalLines;
    }
};

# endif //NETWORKANALYZER_CSV_READER_H
