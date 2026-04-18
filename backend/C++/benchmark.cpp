# include <chrono>
# include <iomanip>
# include <iostream>
# include <string>
# include <vector>

# include "CSVReader.h"
# include "Graph.h"

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
    const std::vector threadCounts = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
    };

    std::cout << "\n========== Performance Benchmark ==========\n";
    std::cout << std::left << std::setw(10) << "Threads"
            << std::setw(20) << "CSV Load (ms)"
            << std::setw(20) << "Neighbor Analysis (ms)" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    for (const int t: threadCounts) {
        CSVReader reader(csvPath, t);

        Timer t1;
        Graph g = reader.readCSV();
        const double csvTime = t1.elapsed_ms();

        Timer t2;
        auto neighbors = g.analyzeNeighbors(t);
        const double analysisTime = t2.elapsed_ms();

        std::cout << std::left << std::setw(10) << t
                << std::setw(20) << csvTime
                << std::setw(20) << analysisTime << std::endl;
    }
    std::cout << "============================================================\n";
}

int main(const int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <csv-path>\n";
        return 1;
    }

    runPerformanceBenchmark(argv[1]);
    return 0;
}
