#include <chrono>
#include <iostream>
#include <vector>
#include <iomanip>
#include "Graph.h"
#include "CSVReader.h"

// 计时器辅助类
class Timer {
    std::chrono::high_resolution_clock::time_point start;

public:
    Timer() : start(std::chrono::high_resolution_clock::now()) {
    }

    [[nodiscard]] double elapsed_ms() const {
        const auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }
};

void runPerformanceBenchmark(const std::string &csvPath) {
    // 测试的线程数序列
    const std::vector threadCounts = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };

    std::cout << "\n========== Performance Benchmark ==========\n";
    std::cout << std::left << std::setw(10) << "Threads"
            << std::setw(20) << "CSV Load (ms)"
            << std::setw(20) << "Neighbor Analysis (ms)" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    for (const int t: threadCounts) {
        // --- 测试 1: CSVReader (全局锁写入) ---
        CSVReader reader(csvPath, t);

        Timer t1;
        Graph g = reader.readCSV(); // 数据加载
        const double csvTime = t1.elapsed_ms();

        // --- 测试 2: analyzeNeighbors (细粒度锁) ---
        // 为了测试分析速度，我们需要一个已经加载好数据的图
        Timer t2;
        auto neighbors = g.analyzeNeighbors(t);
        const double analysisTime = t2.elapsed_ms();

        std::cout << std::left << std::setw(10) << t
                << std::setw(20) << csvTime
                << std::setw(20) << analysisTime << std::endl;
    }
    std::cout << "============================================================\n";
}


int main() {
    runPerformanceBenchmark(R"(C:\Users\Na_Bian\Desktop\NetworkAnalyzer\111_converted.csv)");
    return 0;
}
