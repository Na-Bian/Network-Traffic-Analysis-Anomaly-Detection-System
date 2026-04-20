//
// Created by Na_Bian on 2026/3/3.
//

# ifndef NETWORKANALYZER_CSV_READER_H
# define NETWORKANALYZER_CSV_READER_H

# include "Graph.h"

# include <fstream>
# include <future>
# include <unordered_set>
# include <sstream>
# include <iostream>
# include <thread>
# include <utility>
# include <limits>
# include <algorithm>
# include <cctype>


class CSVReader {
    std::string CSVFile; // CSV文件名
    unsigned int totalBytes = 0; // CSV文件的总字节数
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
        const int parsed = std::stoi(value, &pos);
        if (pos != value.size()) throw std::invalid_argument(fieldName + "包含非数字字符: " + value);
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

    //辅助函数readNextLines用于从CSV文件中读取若干行数据
    std::string readNextLines(std::ifstream &fin, const unsigned int linesToRead) const {
        if (totalLines == 0) return "";
        std::string chunk; // 存储读取的行数据
        chunk.reserve(totalBytes / totalLines * linesToRead); // 按每行平均字节数预先分配字符串空间
        std::string line;
        for (unsigned int i = 0; i < linesToRead && std::getline(fin, line); ++i) {
            chunk += line; // 将读取的行数据添加到块字符串中
            chunk += '\n'; // 添加换行符分隔行数据
        }
        return chunk;
    }

public:
    //构造函数，接受CSV文件名
    explicit CSVReader(std::string fileName = "network_data.csv",
                       const unsigned int threads = Graph::defaultThreadCount())
        : CSVFile(std::move(fileName)), numThreads(threads) {
        std::ifstream fin(CSVFile, std::ios::binary | std::ios::ate); //以二进制模式打开CSV文件，并将文件指针移动到文件末尾
        if (threads < 1) throw std::invalid_argument("线程数量必须至少为1");
        if (!fin.is_open()) throw std::runtime_error("无法打开文件: " + CSVFile);
        totalBytes = static_cast<unsigned int>(fin.tellg()); //获取CSV文件的总字节数
        fin.close();
    }

    //函数readCSV用于从CSV文件中读取网络数据，并将其构建为一个Graph对象
    //参数numThreads指定用于读取和处理CSV文件的线程数量，默认为当前计算机CPU的核心数
    [[nodiscard]] Graph readCSV() {
        std::unordered_set<uint32_t> uniqueIPs; // 存储唯一的IP地址
        std::ifstream fin(CSVFile);
        std::string line;
        std::getline(fin, line); // 跳过标题行
        unsigned int linesCount = 0; // 统计总行数
        while (std::getline(fin, line)) {
            ++linesCount;
            try {
                const Record record = parseRecord(line);
                uniqueIPs.insert(record.srcIP.getIP());
                uniqueIPs.insert(record.dstIP.getIP());
            } catch (const std::exception &e) {
                std::cout << "数据行格式错误(第" << linesCount + 1 << "行): " << line
                        << " 错误信息: " << e.what() << std::endl;
            }
        }

        totalLines = linesCount; // 记录总行数，供后续分块处理使用

        fin.close();

        // 构建Graph对象
        Graph graph;
        graph.reserve(uniqueIPs.size()); // 预先分配节点空间，减少后续添加节点时的重新分配次数

        fin.open(CSVFile);
        std::getline(fin, line); // 跳过标题行

        std::vector<std::future<Graph> > futures; //存储线程的future对象

        const unsigned int workerCount = std::min({
            numThreads,
            Graph::defaultThreadCount(),
            (std::max)(1u, linesCount)
        });
        const unsigned int base = linesCount / workerCount; //计算每个线程需要处理的行数
        const unsigned int remainder = linesCount % workerCount; //计算余数

        //分块并行读取和处理CSV文件
        unsigned int firstLineInChunk = 2;
        for (unsigned int i = 0; i < workerCount; ++i) {
            const unsigned int linesToRead = (i < remainder) ? base + 1 : base; //前remainder个线程处理base+1行，其他线程处理base行
            if (linesToRead == 0) continue;
            const unsigned int chunkFirstLine = firstLineInChunk;
            std::string chunk = readNextLines(fin, linesToRead); // 读取若干行数据作为一个块
            firstLineInChunk += linesToRead;
            futures.push_back(std::async(std::launch::async, [chunk = std::move(chunk), chunkFirstLine]() {
                std::stringstream ss(chunk); //将块数据转换为字符串流，逐行解析
                std::string string;
                unsigned int lineNumber = chunkFirstLine;
                Graph localGraph;

                while (std::getline(ss, string)) {
                    try {
                        const Record record = parseRecord(string);
                        localGraph.addRecord(record.srcIP, record.dstIP, record.protocol, record.srcPort,
                                             record.dstPort,
                                             record.dataSize, record.duration);
                    } catch (const std::exception &e) {
                        std::cout << "数据行格式错误(第" << lineNumber << "行): " << string
                                << " 错误信息: " << e.what() << std::endl;
                    }
                    ++lineNumber;
                }
                return localGraph;
            }));
        }

        for (auto &f: futures) {
            graph.mergeFrom(f.get());
        }

        fin.close();
        return graph;
    }
};

# endif //NETWORKANALYZER_CSV_READER_H
