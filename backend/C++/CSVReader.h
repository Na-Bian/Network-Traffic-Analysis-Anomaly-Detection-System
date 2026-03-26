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


class CSVReader {
    std::string CSVFile; // CSV文件名
    unsigned int totalBytes = 0; // CSV文件的总字节数
    unsigned int totalLines = 0; // CSV文件的总行数
    unsigned int numThreads = 1; //用于读取和处理CSV文件的线程数量

    //辅助函数getNextField用于从数据的每一行中提取下一个字段，直到行末
    static std::string getNextField(std::stringstream &ss) {
        std::string field;
        return getline(ss, field, ',') ? field : ""; // 如果内容为空，返回空字符串
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
                       const unsigned int threads =
                               std::thread::hardware_concurrency() >= 4 ? 4 : std::thread::hardware_concurrency())
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
            std::stringstream ss(line);
            std::string srcIPStr = getNextField(ss);
            std::string dstIPStr = getNextField(ss);
            // 跳过空字段
            if (srcIPStr.empty() || dstIPStr.empty()) continue;

            // 转换为整数IP并插入集合
            try {
                uniqueIPs.insert(IPAddress(srcIPStr).getIP());
                uniqueIPs.insert(IPAddress(dstIPStr).getIP());
            } catch (const std::exception &e) {
                std::cout << "数据行格式错误: " << line << " 错误信息: " << e.what() << std::endl;
            }
        }

        totalLines = linesCount; // 记录总行数，供后续分块处理使用

        fin.close();

        // 构建Graph对象
        Graph graph;
        graph.reserve(uniqueIPs.size()); // 预先分配节点空间，减少后续添加节点时的重新分配次数

        fin.open(CSVFile);
        std::getline(fin, line); // 跳过标题行

        std::mutex graphMutex; //用于保护Graph对象的互斥锁，确保多线程访问Graph对象时的线程安全
        std::vector<std::future<void> > futures; //存储线程的future对象

        const unsigned int base = linesCount / numThreads; //计算每个线程需要处理的行数
        const unsigned int remainder = linesCount % numThreads; //计算余数

        //分块并行读取和处理CSV文件
        for (unsigned int i = 0; i < numThreads; ++i) {
            const unsigned int linesToRead = (i < remainder) ? base + 1 : base; //前remainder个线程处理base+1行，其他线程处理base行
            if (linesToRead == 0) continue;
            std::string chunk = readNextLines(fin, linesToRead); // 读取若干行数据作为一个块
            futures.push_back(std::async(std::launch::async, [chunk, &graph, &graphMutex]() {
                std::stringstream ss(chunk); //将块数据转换为字符串流，逐行解析
                std::string string;

                while (std::getline(ss, string)) {
                    std::stringstream lineStream(string);
                    std::string srcIPStr = getNextField(lineStream);
                    std::string dstIPStr = getNextField(lineStream);
                    std::string protocolStr = getNextField(lineStream);
                    std::string srcPortStr = getNextField(lineStream);
                    std::string dstPortStr = getNextField(lineStream);
                    std::string dataSizeStr = getNextField(lineStream);
                    std::string durationStr = getNextField(lineStream);

                    // 数据有效性验证和转换
                    if (srcIPStr.empty() || dstIPStr.empty() || protocolStr.empty()) {
                        std::cout << "数据行格式错误: " << string << std::endl;
                        continue;
                    }

                    try {
                        uint8_t protocol = std::stoi(protocolStr);
                        uint16_t srcPort = srcPortStr.empty() ? 0 : static_cast<uint16_t>(std::stoi(srcPortStr));
                        uint16_t dstPort = dstPortStr.empty() ? 0 : static_cast<uint16_t>(std::stoi(dstPortStr));
                        int dataSize = dataSizeStr.empty() ? 0 : std::stoi(dataSizeStr);
                        double duration = durationStr.empty() ? 0.0 : std::stod(durationStr);
                        IPAddress srcIP(srcIPStr.c_str());
                        IPAddress dstIP(dstIPStr.c_str());

                        std::lock_guard lock(graphMutex); // 加锁，确保线程安全地访问Graph对象

                        graph.addRecord(srcIP, dstIP, protocol, srcPort, dstPort, dataSize, duration);
                    } catch (const std::exception &e) {
                        std::cout << "数据行格式错误: " << string << " 错误信息: " << e.what() << std::endl;
                    }
                }
            }));
        }

        for (auto &f: futures) f.wait(); // 等待所有块解析完成

        fin.close();
        return graph;
    }
};

# endif //NETWORKANALYZER_CSV_READER_H
