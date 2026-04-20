// main.cpp

#ifdef _WIN32
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <windows.h>
#endif

#include "CSVReader.h"
#include "CustomRule.h"
#include "Graph.h"
#include "SubgraphExporter.h"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <variant>

using namespace std;

void printUsage(const char *progName);

namespace {
    using JsonScalar = variant<monostate, bool, double, string>;

    string trim(const string &value) {
        const auto begin = value.find_first_not_of(" \t\r\n");
        if (begin == string::npos) return "";
        const auto end = value.find_last_not_of(" \t\r\n");
        return value.substr(begin, end - begin + 1);
    }

    class JsonWriter {
    public:
        JsonWriter() {
            out_ << '{';
        }

        static string escape(const string &value) {
            ostringstream escaped;
            for (const unsigned char ch: value) {
                switch (ch) {
                    case '\\': escaped << "\\\\";
                        break;
                    case '"': escaped << "\\\"";
                        break;
                    case '\b': escaped << "\\b";
                        break;
                    case '\f': escaped << "\\f";
                        break;
                    case '\n': escaped << "\\n";
                        break;
                    case '\r': escaped << "\\r";
                        break;
                    case '\t': escaped << "\\t";
                        break;
                    default:
                        if (ch < 0x20) {
                            escaped << "\\u"
                                    << hex << setw(4) << setfill('0')
                                    << static_cast<int>(ch)
                                    << dec << setfill(' ');
                        } else {
                            escaped << static_cast<char>(ch);
                        }
                }
            }
            return escaped.str();
        }

        void stringField(const string &name, const string &value) {
            writeName(name);
            out_ << '"' << escape(value) << '"';
        }

        void numberField(const string &name, const double value) {
            writeName(name);
            out_ << setprecision(12) << value;
        }

        void integerField(const string &name, const long long value) {
            writeName(name);
            out_ << value;
        }

        void boolField(const string &name, const bool value) {
            writeName(name);
            out_ << (value ? "true" : "false");
        }

        void nullField(const string &name) {
            writeName(name);
            out_ << "null";
        }

        void rawField(const string &name, const string &rawJson) {
            writeName(name);
            out_ << rawJson;
        }

        void stringArrayField(const string &name, const vector<string> &values) {
            writeName(name);
            out_ << '[';
            bool first = true;
            for (const auto &value: values) {
                if (!first) out_ << ',';
                first = false;
                out_ << '"' << escape(value) << '"';
            }
            out_ << ']';
        }

        string finish() {
            out_ << '}';
            return out_.str();
        }

    private:
        ostringstream out_;
        bool firstField_ = true;

        void writeName(const string &name) {
            if (!firstField_) out_ << ',';
            firstField_ = false;
            out_ << '"' << escape(name) << "\":";
        }
    };

    class FlatJsonParser {
    public:
        explicit FlatJsonParser(string source) : source_(std::move(source)) {
        }

        unordered_map<string, JsonScalar> parseObject() {
            skipWhitespace();
            expect('{');
            unordered_map<string, JsonScalar> object;
            skipWhitespace();
            if (peek() == '}') {
                ++position_;
                return object;
            }

            while (true) {
                skipWhitespace();
                const string key = parseString();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                object[key] = parseScalar();
                skipWhitespace();
                const char next = peek();
                if (next == ',') {
                    ++position_;
                    continue;
                }
                if (next == '}') {
                    ++position_;
                    break;
                }
                throw runtime_error("JSON 对象格式错误");
            }
            return object;
        }

    private:
        string source_;
        size_t position_ = 0;

        [[nodiscard]] char peek() const {
            if (position_ >= source_.size()) {
                throw runtime_error("JSON 提前结束");
            }
            return source_[position_];
        }

        void skipWhitespace() {
            while (position_ < source_.size() && isspace(static_cast<unsigned char>(source_[position_])) != 0) {
                ++position_;
            }
        }

        void expect(const char expected) {
            if (peek() != expected) {
                throw runtime_error(string("JSON 解析失败，期待字符: ") + expected);
            }
            ++position_;
        }

        string parseString() {
            expect('"');
            ostringstream out;
            while (position_ < source_.size()) {
                const char ch = source_[position_++];
                if (ch == '"') {
                    return out.str();
                }
                if (ch != '\\') {
                    out << ch;
                    continue;
                }
                if (position_ >= source_.size()) {
                    throw runtime_error("JSON 字符串转义不完整");
                }
                switch (source_[position_++]) {
                    case '"': out << '"';
                        break;
                    case '\\': out << '\\';
                        break;
                    case '/': out << '/';
                        break;
                    case 'b': out << '\b';
                        break;
                    case 'f': out << '\f';
                        break;
                    case 'n': out << '\n';
                        break;
                    case 'r': out << '\r';
                        break;
                    case 't': out << '\t';
                        break;
                    case 'u': {
                        if (position_ + 4 > source_.size()) {
                            throw runtime_error("JSON unicode 转义不完整");
                        }
                        const string hexCode = source_.substr(position_, 4);
                        position_ += 4;
                        const int codePoint = stoi(hexCode, nullptr, 16);
                        if (codePoint <= 0x7F) {
                            out << static_cast<char>(codePoint);
                        } else {
                            out << '?';
                        }
                        break;
                    }
                    default:
                        throw runtime_error("JSON 包含不支持的转义字符");
                }
            }
            throw runtime_error("JSON 字符串未闭合");
        }

        JsonScalar parseScalar() {
            const char ch = peek();
            if (ch == '"') {
                return parseString();
            }
            if ((ch >= '0' && ch <= '9') || ch == '-') {
                size_t end = position_;
                while (end < source_.size()) {
                    const char curr = source_[end];
                    if ((curr >= '0' && curr <= '9') || curr == '-' || curr == '+' || curr == '.' || curr == 'e' ||
                        curr == 'E') {
                        ++end;
                        continue;
                    }
                    break;
                }
                const string token = source_.substr(position_, end - position_);
                position_ = end;
                return stod(token);
            }
            if (source_.compare(position_, 4, "true") == 0) {
                position_ += 4;
                return true;
            }
            if (source_.compare(position_, 5, "false") == 0) {
                position_ += 5;
                return false;
            }
            if (source_.compare(position_, 4, "null") == 0) {
                position_ += 4;
                return monostate{};
            }
            throw runtime_error("JSON 仅支持标量请求字段");
        }
    };

    string requireString(const unordered_map<string, JsonScalar> &object, const string &key) {
        const auto it = object.find(key);
        if (it == object.end()) {
            throw invalid_argument("缺少字段: " + key);
        }
        if (!holds_alternative<string>(it->second)) {
            throw invalid_argument("字段类型错误: " + key);
        }
        return get<string>(it->second);
    }

    string optionalString(const unordered_map<string, JsonScalar> &object, const string &key,
                          const string &defaultValue = "") {
        const auto it = object.find(key);
        if (it == object.end() || holds_alternative<monostate>(it->second)) return defaultValue;
        if (!holds_alternative<string>(it->second)) {
            throw invalid_argument("字段类型错误: " + key);
        }
        return get<string>(it->second);
    }

    int optionalInt(const unordered_map<string, JsonScalar> &object, const string &key, const int defaultValue) {
        const auto it = object.find(key);
        if (it == object.end() || holds_alternative<monostate>(it->second)) return defaultValue;
        if (!holds_alternative<double>(it->second)) {
            throw invalid_argument("字段类型错误: " + key);
        }
        return static_cast<int>(llround(get<double>(it->second)));
    }

    size_t optionalSize(const unordered_map<string, JsonScalar> &object, const string &key, const size_t defaultValue) {
        const auto it = object.find(key);
        if (it == object.end() || holds_alternative<monostate>(it->second)) return defaultValue;
        if (!holds_alternative<double>(it->second)) {
            throw invalid_argument("字段类型错误: " + key);
        }
        return static_cast<size_t>(llround(get<double>(it->second)));
    }

    long long optionalLongLong(const unordered_map<string, JsonScalar> &object, const string &key,
                               const long long defaultValue) {
        const auto it = object.find(key);
        if (it == object.end() || holds_alternative<monostate>(it->second)) return defaultValue;
        if (!holds_alternative<double>(it->second)) {
            throw invalid_argument("字段类型错误: " + key);
        }
        return static_cast<long long>(llround(get<double>(it->second)));
    }

    double optionalDouble(const unordered_map<string, JsonScalar> &object, const string &key,
                          const double defaultValue) {
        const auto it = object.find(key);
        if (it == object.end() || holds_alternative<monostate>(it->second)) return defaultValue;
        if (!holds_alternative<double>(it->second)) {
            throw invalid_argument("字段类型错误: " + key);
        }
        return get<double>(it->second);
    }

    void emitJsonLine(const string &line) {
        cout << line << '\n';
        cout.flush();
    }

    void emitProgress(const string &requestId, const string &phase, const double progress, const string &message) {
        JsonWriter writer;
        writer.stringField("request_id", requestId);
        writer.stringField("event", "progress");
        writer.stringField("phase", phase);
        writer.numberField("progress", progress);
        writer.stringField("message", message);
        emitJsonLine(writer.finish());
    }

    void emitError(const string &requestId, const string &phase, const string &message) {
        JsonWriter writer;
        writer.stringField("request_id", requestId);
        writer.stringField("event", "error");
        writer.stringField("phase", phase);
        writer.stringField("error", message);
        writer.stringField("message", message);
        emitJsonLine(writer.finish());
    }

    void emitComplete(const string &requestId,
                      const string &phase,
                      const string &message,
                      const vector<string> &resultLines = {},
                      const string &resultPath = "",
                      const string &metadataJson = "null",
                      const string &resultPayloadJson = "null") {
        JsonWriter writer;
        writer.stringField("request_id", requestId);
        writer.stringField("event", "complete");
        writer.stringField("phase", phase);
        writer.numberField("progress", 1.0);
        writer.stringField("message", message);
        writer.stringArrayField("result_lines", resultLines);
        if (!resultPath.empty()) writer.stringField("result_path", resultPath);
        else writer.nullField("result_path");
        writer.rawField("metadata", metadataJson);
        writer.rawField("result_payload", resultPayloadJson);
        emitJsonLine(writer.finish());
    }

    uint64_t lastWriteTick(const string &path) {
        try {
            const auto time = filesystem::last_write_time(path);
            return static_cast<uint64_t>(time.time_since_epoch().count());
        } catch (...) {
            return 0;
        }
    }

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

    struct TaskRunResult {
        vector<string> lines;
        string resultPath;
    };

    struct PortScanCacheEntry {
        set<PortScanner> scanners;
    };

    struct DDoSCacheEntry {
        set<DDoSTarget> targets;
    };

    struct StarCacheEntry {
        vector<StarStructure> stars;
    };

    struct SessionState {
        optional<Graph> graph;
        string inputFile;
        uint64_t inputMtime = 0;
        unsigned int threads = Graph::defaultThreadCount();
        size_t recordCount = 0;
        optional<vector<unordered_map<int, NeighborInfo> > > neighborsCache;
        optional<vector<pair<IPAddress, long long> > > totalTrafficCache;
        optional<vector<pair<IPAddress, long long> > > httpsTrafficCache;
        unordered_map<string, vector<tuple<IPAddress, long long, double> > > outRatioCache;
        unordered_map<string, PortScanCacheEntry> portScanCache;
        unordered_map<string, DDoSCacheEntry> ddosCache;
        unordered_map<string, StarCacheEntry> starCache;

        void clearCaches() {
            neighborsCache.reset();
            totalTrafficCache.reset();
            httpsTrafficCache.reset();
            outRatioCache.clear();
            portScanCache.clear();
            ddosCache.clear();
            starCache.clear();
        }

        [[nodiscard]] bool loaded() const {
            return graph.has_value();
        }

        [[nodiscard]] const Graph &requireGraph() const {
            if (!graph.has_value()) {
                throw runtime_error("当前会话尚未加载数据集");
            }
            return *graph;
        }
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

    void validateArguments(ParsedArgs &args, const bool requireInputFile) {
        if (requireInputFile && args.inputFile.empty()) {
            throw invalid_argument("必须指定 --input");
        }
        if (args.task.empty()) {
            throw invalid_argument("必须指定任务");
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

    ParsedArgs parseTaskRequest(const unordered_map<string, JsonScalar> &request, const SessionState &state) {
        ParsedArgs args;
        args.task = requireString(request, "task");
        args.inputFile = state.inputFile;
        args.threads = optionalInt(request, "threads", static_cast<int>(state.threads));
        args.outputJsonFile = optionalString(request, "output_json");
        args.targetIP = optionalString(request, "target");
        args.srcIP = optionalString(request, "src");
        args.dstIP = optionalString(request, "dst");
        args.sortType = optionalString(request, "sort_type", "total");
        args.ratioThreshold = optionalDouble(request, "ratio_threshold", 0.8);
        args.inRatioThreshold = optionalDouble(request, "in_ratio_threshold", 0.8);
        args.threshold = optionalInt(request, "threshold", 0);
        args.maxPaths = optionalSize(request, "max_paths", DEFAULT_MAX_PATHS);
        args.inDataThreshold = optionalLongLong(request, "in_data_threshold", 1LL << 30);
        args.minTraffic = optionalLongLong(request, "min_traffic", 0);
        args.ruleTarget = optionalString(request, "rule_target");
        args.rangeCIDR = optionalString(request, "range_cidr");
        args.rangeStart = optionalString(request, "range_start");
        args.rangeEnd = optionalString(request, "range_end");
        args.ruleTypeStr = optionalString(request, "rule_type");
        args.ruleProtocol = static_cast<uint8_t>(optionalInt(request, "rule_protocol", 0));
        args.ruleSrcPort = static_cast<uint16_t>(optionalInt(request, "rule_src_port", 0));
        args.ruleDstPort = static_cast<uint16_t>(optionalInt(request, "rule_dst_port", 0));
        args.maxTraffic = optionalLongLong(request, "rule_max_traffic", (numeric_limits<long long>::max)());
        args.hasCIDR = !args.rangeCIDR.empty();
        args.hasStartEnd = !args.rangeStart.empty() || !args.rangeEnd.empty();
        validateArguments(args, false);
        return args;
    }

    void printNoPathFound(TaskRunResult &result, const string &srcIP, const string &dstIP) {
        result.lines.push_back("没有找到从 " + srcIP + " 到 " + dstIP + " 的路径");
    }

    void appendPathInfoList(TaskRunResult &result, const Graph &graph, const vector<PathInfo> &paths,
                            const string &metricName) {
        for (const auto &[path, metricValue]: paths) {
            ostringstream line;
            for (const int idx: path) {
                line << graph.getVertexIP(idx).toString() << ' ';
            }
            line << "| " << metricName << "=" << metricValue;
            result.lines.push_back(trim(line.str()));
        }
    }

    void appendSinglePathTaskResult(TaskRunResult &result, const Graph &graph, const vector<PathInfo> &paths,
                                    const string &title, const string &metricName, const string &srcIP,
                                    const string &dstIP) {
        result.lines.push_back(title);
        if (paths.empty()) {
            printNoPathFound(result, srcIP, dstIP);
            return;
        }
        appendPathInfoList(result, graph, paths, metricName);
    }

    const vector<unordered_map<int, NeighborInfo> > &warmNeighbors(SessionState &state,
                                                                   const unsigned int requestedThreads,
                                                                   const string &requestId = "") {
        if (state.neighborsCache.has_value()) {
            return *state.neighborsCache;
        }
        const Graph &graph = state.requireGraph();
        if (!requestId.empty()) {
            emitProgress(requestId, "index_warmup", 0.76, "正在构建邻居缓存...");
        }
        state.neighborsCache = graph.analyzeNeighbors(requestedThreads, [&](const string &message) {
            if (requestId.empty()) return;
            double progress = 0.84;
            if (message.find("第一阶段") != string::npos) progress = 0.88;
            else if (message.find("第二阶段") != string::npos) progress = 0.93;
            emitProgress(requestId, "index_warmup", progress, message);
        });
        return *state.neighborsCache;
    }

    string thresholdKey(const double value) {
        ostringstream stream;
        stream << fixed << setprecision(6) << value;
        return stream.str();
    }

    string buildPortScanCacheKey(const ParsedArgs &args) {
        ostringstream stream;
        stream << "thr=" << (args.threshold > 0 ? args.threshold : 20)
                << "|ratio=" << thresholdKey(args.ratioThreshold)
                << "|min=" << args.minTraffic;
        return stream.str();
    }

    string buildDDoSCacheKey(const ParsedArgs &args) {
        ostringstream stream;
        stream << "thr=" << (args.threshold > 0 ? args.threshold : 20)
                << "|in=" << args.inDataThreshold
                << "|ratio=" << thresholdKey(args.inRatioThreshold);
        return stream.str();
    }

    string buildStarCacheKey(const ParsedArgs &args) {
        return "thr=" + to_string(args.threshold > 0 ? args.threshold : 20);
    }

    const vector<pair<IPAddress, long long> > &cachedTotalTraffic(SessionState &state) {
        if (!state.totalTrafficCache.has_value()) {
            state.totalTrafficCache = state.requireGraph().getNodesSortedByTotalTraffic();
        }
        return *state.totalTrafficCache;
    }

    const vector<pair<IPAddress, long long> > &cachedHttpsTraffic(SessionState &state) {
        if (!state.httpsTrafficCache.has_value()) {
            state.httpsTrafficCache = state.requireGraph().getNodesWithHTTPSortedByTraffic();
        }
        return *state.httpsTrafficCache;
    }

    const vector<tuple<IPAddress, long long, double> > &cachedOutRatio(SessionState &state, const double threshold) {
        const string key = thresholdKey(threshold);
        auto it = state.outRatioCache.find(key);
        if (it == state.outRatioCache.end()) {
            it = state.outRatioCache.emplace(key, state.requireGraph().getNodesWithOutRatioAbove(threshold)).first;
        }
        return it->second;
    }

    vector<StarStructure> findStarStructuresFromNeighbors(const Graph &graph,
                                                          const vector<unordered_map<int, NeighborInfo> > &neighbors,
                                                          const int degreeThreshold,
                                                          const unsigned int numThreads,
                                                          const Graph::ProgressCallback &progressCallback) {
        const int n = static_cast<int>(neighbors.size());
        const unsigned int threadCount = Graph::effectiveThreadCount(numThreads, n);
        if (progressCallback) {
            progressCallback(
                "进度: 星型结构筛选开始，节点数=" + to_string(n) +
                "，线程数=" + to_string(threadCount)
            );
        }

        vector<future<vector<StarStructure> > > futures;
        const int base = n / static_cast<int>(threadCount);
        const int remainder = n % static_cast<int>(threadCount);
        int start = 0;
        int end = -1;
        for (int i = 0; i < static_cast<int>(threadCount); ++i) {
            const int nodesToRead = i < remainder ? base + 1 : base;
            start = end + 1;
            end = start + nodesToRead - 1;
            if (start > end) break;
            futures.push_back(async(std::launch::async, [&graph, &neighbors, start, end, degreeThreshold]() {
                vector<StarStructure> localStars;
                for (int index = start; index <= end; ++index) {
                    const auto &currNeighbors = neighbors[index];
                    const IPAddress centerNode = graph.getVertexIP(index);
                    const long long inData = graph.getVertexInData(index);
                    const long long outData = graph.getVertexOutData(index);
                    const long long totalData = inData + outData;

                    vector<pair<IPAddress, long long> > neighborIPs;
                    int totalLeaves = 0;
                    for (const auto &[neighborIndex, info]: currNeighbors) {
                        if (neighbors[neighborIndex].size() == 1) {
                            ++totalLeaves;
                            neighborIPs.emplace_back(graph.getVertexIP(neighborIndex), info.InData + info.OutData);
                        }
                    }

                    if (totalLeaves > degreeThreshold) {
                        const double leafRatio = currNeighbors.empty()
                                                     ? 0.0
                                                     : static_cast<double>(totalLeaves) /
                                                       static_cast<double>(currNeighbors.size());
                        localStars.push_back(
                            {centerNode, move(neighborIPs), totalData, inData, outData, leafRatio}
                        );
                    }
                }
                return localStars;
            }));
        }

        vector<StarStructure> starStructures;
        for (auto &future: futures) {
            auto local = future.get();
            starStructures.insert(
                starStructures.end(),
                make_move_iterator(local.begin()),
                make_move_iterator(local.end())
            );
        }
        if (progressCallback) {
            progressCallback("进度: 星型结构检测完成，命中 " + to_string(starStructures.size()) + " 个中心节点");
        }
        return starStructures;
    }

    template<typename T, typename Accessor>
    vector<ConnectedComponents> buildNeighborhoodComponents(
        const Graph &graph,
        const set<T> &items,
        const vector<unordered_map<int, NeighborInfo> > &neighbors,
        Accessor accessor) {
        vector<ConnectedComponents> components;
        for (const auto &item: items) {
            const int centerIndex = graph.findVertexIndex(accessor(item));
            if (centerIndex == -1) continue;

            ConnectedComponents component;
            component.nodes.insert(centerIndex);
            for (const auto &[neighborIndex, info]: neighbors[centerIndex]) {
                component.nodes.insert(neighborIndex);
                component.edges.insert({centerIndex, neighborIndex, info.InData + info.OutData});
            }
            components.push_back(move(component));
        }
        return components;
    }

    TaskRunResult runFlowSortTask(const Graph &graph, const ParsedArgs &args, SessionState *state) {
        TaskRunResult result;
        if (args.sortType == "total") {
            const auto &sorted = state ? cachedTotalTraffic(*state) : graph.getNodesSortedByTotalTraffic();
            result.lines.emplace_back("节点总流量排序 (IP, 总流量):");
            for (const auto &[ip, traffic]: sorted) {
                result.lines.push_back(ip.toString() + "," + to_string(traffic));
            }
            return result;
        }
        if (args.sortType == "https") {
            const auto &sorted = state ? cachedHttpsTraffic(*state) : graph.getNodesWithHTTPSortedByTraffic();
            result.lines.emplace_back("HTTPS节点流量排序 (IP, HTTPS流量):");
            for (const auto &[ip, traffic]: sorted) {
                result.lines.push_back(ip.toString() + "," + to_string(traffic));
            }
            return result;
        }
        const auto &sorted = state
                                 ? cachedOutRatio(*state, args.ratioThreshold)
                                 : graph.getNodesWithOutRatioAbove(
                                     args.ratioThreshold);
        result.lines.push_back("出流量占比 >= " + to_string(args.ratioThreshold) + " 的节点排序 (IP, 总流量, 出流量占比):");
        for (const auto &[ip, total, ratio]: sorted) {
            ostringstream line;
            line << ip.toString() << "," << total << "," << ratio;
            result.lines.push_back(line.str());
        }
        return result;
    }

    TaskRunResult runSinglePathTask(const Graph &graph, const ParsedArgs &args) {
        TaskRunResult result;
        if (args.task == "min-congestion") {
            const auto paths = graph.minCongestion(*args.srcAddress, *args.dstAddress, args.maxPaths);
            appendSinglePathTaskResult(
                result, graph, paths, "最小拥塞路径 (共 " + to_string(paths.size()) + " 条):", "congestion", args.srcIP,
                args.dstIP
            );
            if (!args.outputJsonFile.empty()) {
                SubgraphExporter(graph).exportPathsAsSubgraph(paths, args.outputJsonFile);
                result.lines.push_back("路径子图已导出到 " + args.outputJsonFile);
                result.resultPath = args.outputJsonFile;
            }
            return result;
        }
        if (args.task == "min-hop") {
            int minHopCount = 0;
            const auto paths = graph.minHop(*args.srcAddress, *args.dstAddress, minHopCount, args.maxPaths);
            appendSinglePathTaskResult(
                result, graph, paths, "最小跳数路径 (最小跳数 = " + to_string(minHopCount) + "):", "congestion",
                args.srcIP, args.dstIP
            );
            if (!args.outputJsonFile.empty()) {
                SubgraphExporter(graph).exportPathsAsSubgraph(paths, args.outputJsonFile);
                result.lines.push_back("路径子图已导出到 " + args.outputJsonFile);
                result.resultPath = args.outputJsonFile;
            }
            return result;
        }

        double minRiskLevel = 0;
        const auto paths = graph.minCostCustom(*args.srcAddress, *args.dstAddress, minRiskLevel, args.maxPaths);
        appendSinglePathTaskResult(
            result, graph, paths, "最小风险路径 (最小风险值 = " + to_string(minRiskLevel) + "):", "risk", args.srcIP,
            args.dstIP
        );
        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).exportPathsAsSubgraph(paths, args.outputJsonFile);
            result.lines.push_back("路径子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
        }
        return result;
    }

    TaskRunResult runComparePathsTask(const Graph &graph, const ParsedArgs &args) {
        TaskRunResult result;
        const auto pathsCong = graph.minCongestion(*args.srcAddress, *args.dstAddress, args.maxPaths);
        appendSinglePathTaskResult(
            result, graph, pathsCong, "最小拥塞路径 (共 " + to_string(pathsCong.size()) + " 条):", "congestion",
            args.srcIP, args.dstIP
        );

        int minHopCount = 0;
        const auto pathsHop = graph.minHop(*args.srcAddress, *args.dstAddress, minHopCount, args.maxPaths);
        appendSinglePathTaskResult(
            result, graph, pathsHop, "最小跳数路径 (最小跳数 = " + to_string(minHopCount) + "):", "congestion",
            args.srcIP, args.dstIP
        );

        double minRiskLevel = 0;
        const auto pathsRisk = graph.minCostCustom(*args.srcAddress, *args.dstAddress, minRiskLevel, args.maxPaths);
        appendSinglePathTaskResult(
            result, graph, pathsRisk, "最小风险路径 (最小风险值 = " + to_string(minRiskLevel) + "):", "risk",
            args.srcIP, args.dstIP
        );

        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).exportPathsAsSubgraph({pathsCong, pathsHop, pathsRisk}, args.outputJsonFile);
            result.lines.push_back("对比路径子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
        }
        return result;
    }

    TaskRunResult runPortScanTask(const Graph &graph, const ParsedArgs &args, SessionState *state,
                                  const Graph::ProgressCallback &progressCallback) {
        TaskRunResult result;
        const int threshold = args.threshold > 0 ? args.threshold : 20;
        bool reusedCache = false;
        set<PortScanner> scanners;
        if (state) {
            const string cacheKey = buildPortScanCacheKey(args);
            const auto cacheIt = state->portScanCache.find(cacheKey);
            if (cacheIt != state->portScanCache.end()) {
                progressCallback("进度: 端口扫描检测复用会话缓存结果...");
                scanners = cacheIt->second.scanners;
                reusedCache = true;
            } else {
                scanners = graph.detectPortScanners(
                    threshold, args.ratioThreshold, args.minTraffic, args.threads, progressCallback
                );
                state->portScanCache.emplace(cacheKey, PortScanCacheEntry{scanners});
            }
        } else {
            scanners = graph.detectPortScanners(
                threshold, args.ratioThreshold, args.minTraffic, args.threads, progressCallback
            );
        }
        result.lines.push_back("检测到端口扫描攻击者 (" + to_string(scanners.size()) + " 个):");
        for (const auto &scanner: scanners) {
            ostringstream line;
            line << scanner.ip.toString() << ","
                    << scanner.portCount << ","
                    << scanner.targetCount << ","
                    << scanner.scanType << ","
                    << scanner.outRatio << ","
                    << scanner.totalTraffic;
            result.lines.push_back(line.str());
        }
        if (reusedCache) {
            result.lines.emplace_back("复用已缓存的端口扫描检测结果");
        }
        if (!args.outputJsonFile.empty()) {
            if (state && state->neighborsCache.has_value()) {
                const auto components = buildNeighborhoodComponents(
                    graph, scanners, *state->neighborsCache, [](const PortScanner &scanner) { return scanner.ip; }
                );
                SubgraphExporter(graph).exportSubGraph(components, args.outputJsonFile);
            } else {
                SubgraphExporter(graph).exportPortScannersAsSubgraph(scanners, args.outputJsonFile);
            }
            result.lines.push_back("端口扫描攻击者子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
        }
        return result;
    }

    TaskRunResult runDDoSTask(const Graph &graph, const ParsedArgs &args, SessionState *state,
                              const Graph::ProgressCallback &progressCallback) {
        TaskRunResult result;
        const int threshold = args.threshold > 0 ? args.threshold : 20;
        bool reusedCache = false;
        set<DDoSTarget> targets;
        if (state) {
            const string cacheKey = buildDDoSCacheKey(args);
            const auto cacheIt = state->ddosCache.find(cacheKey);
            if (cacheIt != state->ddosCache.end()) {
                progressCallback("进度: DDoS 目标检测复用会话缓存结果...");
                targets = cacheIt->second.targets;
                reusedCache = true;
            } else {
                targets = graph.detectDDoSTargets(
                    threshold, args.inDataThreshold, args.inRatioThreshold, args.threads, progressCallback
                );
                state->ddosCache.emplace(cacheKey, DDoSCacheEntry{targets});
            }
        } else {
            targets = graph.detectDDoSTargets(
                threshold, args.inDataThreshold, args.inRatioThreshold, args.threads, progressCallback
            );
        }
        result.lines.push_back("检测到DDoS攻击目标 (" + to_string(targets.size()) + " 个):");
        for (const auto &target: targets) {
            ostringstream line;
            line << target.ip.toString() << ","
                    << target.sourceCount << ","
                    << target.inData << ","
                    << target.inRatio;
            result.lines.push_back(line.str());
        }
        if (reusedCache) {
            result.lines.emplace_back("复用已缓存的 DDoS 检测结果");
        }
        if (!args.outputJsonFile.empty()) {
            if (state && state->neighborsCache.has_value()) {
                const auto components = buildNeighborhoodComponents(
                    graph, targets, *state->neighborsCache, [](const DDoSTarget &target) { return target.ip; }
                );
                SubgraphExporter(graph).exportSubGraph(components, args.outputJsonFile);
            } else {
                SubgraphExporter(graph).exportDDoSTargetsAsSubgraph(targets, args.outputJsonFile);
            }
            result.lines.push_back("DDoS攻击目标子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
        }
        return result;
    }

    TaskRunResult runStarTask(const Graph &graph, const ParsedArgs &args, SessionState *state,
                              const Graph::ProgressCallback &progressCallback) {
        TaskRunResult result;
        const int threshold = args.threshold > 0 ? args.threshold : 20;
        vector<StarStructure> stars;
        bool reusedCache = false;
        if (state) {
            const string cacheKey = buildStarCacheKey(args);
            const auto cacheIt = state->starCache.find(cacheKey);
            if (cacheIt != state->starCache.end()) {
                progressCallback("进度: 星型结构检测复用会话缓存结果...");
                stars = cacheIt->second.stars;
                reusedCache = true;
            } else if (state->neighborsCache.has_value()) {
                progressCallback("进度: 星型结构检测开始，复用已加载邻居缓存...");
                stars = findStarStructuresFromNeighbors(graph, *state->neighborsCache, threshold, args.threads,
                                                        progressCallback);
                state->starCache.emplace(cacheKey, StarCacheEntry{stars});
            } else {
                stars = graph.findStarStructures(threshold, args.threads, progressCallback);
                state->starCache.emplace(cacheKey, StarCacheEntry{stars});
            }
        } else {
            stars = graph.findStarStructures(threshold, args.threads, progressCallback);
        }

        result.lines.push_back("找到星型结构 (" + to_string(stars.size()) + " 个):");
        for (size_t index = 0; index < stars.size(); ++index) {
            const auto &[center, neighbors, totalData, inData, outData, leafRatio] = stars[index];
            ostringstream summary;
            summary << "星型 " << index + 1 << ": 中心=" << center.toString()
                    << ", 邻居数=" << neighbors.size()
                    << ", 总流量=" << totalData
                    << ", 入流量=" << inData
                    << ", 出流量=" << outData
                    << ", 叶子占比=" << leafRatio;
            result.lines.push_back(summary.str());

            ostringstream detail;
            detail << "  邻居 (IP, 流量): ";
            for (const auto &[ip, traffic]: neighbors) {
                detail << ip.toString() << "(" << traffic << ") ";
            }
            result.lines.push_back(trim(detail.str()));
        }
        if (reusedCache) {
            result.lines.emplace_back("复用已缓存的星型结构检测结果");
        }

        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).exportStarStructureAsSubgraph(stars, args.outputJsonFile);
            result.lines.push_back("星型结构子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
        }
        return result;
    }

    TaskRunResult runCustomRuleTask(const Graph &graph, const ParsedArgs &args) {
        TaskRunResult result;
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
        result.lines.push_back("违反规则的通信记录 (" + to_string(violations.size()) + " 条):");
        if (violations.empty()) {
            result.lines.emplace_back("  无违规记录");
        } else {
            for (const auto &violation: violations) {
                ostringstream line;
                line << "  " << violation.getSrcIP().toString() << " -> " << violation.getDstIP().toString()
                        << " [proto=" << static_cast<int>(violation.getProtocol())
                        << ", srcPort=" << violation.getSrcPort()
                        << ", dstPort=" << violation.getDstPort()
                        << "] reason: " << violation.getReason();
                result.lines.push_back(line.str());
            }
        }

        if (!args.outputJsonFile.empty()) {
            SubgraphExporter(graph).
                    exportViolationsAsSubgraph(*args.ruleTargetAddress, violations, args.outputJsonFile);
            result.lines.push_back("违规通信子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
        }
        return result;
    }

    TaskRunResult runTask(const Graph &graph, const ParsedArgs &args, SessionState *state,
                          const Graph::ProgressCallback &progressCallback) {
        if (args.task == "full-graph") {
            if (args.outputJsonFile.empty()) {
                throw invalid_argument("full-graph 任务需要 --output-json");
            }
            progressCallback("进度: 正在导出全网拓扑 JSON...");
            SubgraphExporter exporter(graph);
            if (state && state->neighborsCache.has_value()) {
                exporter.exportSubGraph(graph.findAllComponents(*state->neighborsCache), args.outputJsonFile);
            } else {
                exporter.exportFullGraph(args.outputJsonFile);
            }
            TaskRunResult result;
            result.lines.push_back("全网拓扑已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
            return result;
        }
        if (args.task == "subgraph") {
            progressCallback("进度: 正在导出目标子图 JSON...");
            SubgraphExporter exporter(graph);
            if (state && state->neighborsCache.has_value()) {
                exporter.exportSubGraph(
                    graph.findConnectedComponents(*args.targetAddress, *state->neighborsCache),
                    args.outputJsonFile
                );
            } else {
                exporter.exportSubGraph(*args.targetAddress, args.outputJsonFile);
            }
            TaskRunResult result;
            result.lines.push_back("子图已导出到 " + args.outputJsonFile);
            result.resultPath = args.outputJsonFile;
            return result;
        }
        if (args.task == "flow-sort") return runFlowSortTask(graph, args, state);
        if (isPathTask(args.task)) return runSinglePathTask(graph, args);
        if (args.task == "compare-paths") return runComparePathsTask(graph, args);
        if (args.task == "port-scan") return runPortScanTask(graph, args, state, progressCallback);
        if (args.task == "ddos-target") return runDDoSTask(graph, args, state, progressCallback);
        if (args.task == "star-structures") return runStarTask(graph, args, state, progressCallback);
        return runCustomRuleTask(graph, args);
    }

    string buildDatasetMetadataJson(const SessionState &state) {
        JsonWriter metadata;
        metadata.boolField("loaded", state.loaded());
        metadata.stringField("input_file", state.inputFile);
        metadata.integerField("input_mtime", static_cast<long long>(state.inputMtime));
        metadata.integerField("threads", state.threads);
        metadata.integerField("record_count", static_cast<long long>(state.recordCount));
        if (state.loaded()) {
            metadata.integerField("vertex_count", static_cast<long long>(state.graph->getVertexCount()));
            metadata.integerField("edge_count", static_cast<long long>(state.graph->getEdgeCount()));
            metadata.boolField("neighbor_cache_ready", state.neighborsCache.has_value());
        } else {
            metadata.integerField("vertex_count", 0);
            metadata.integerField("edge_count", 0);
            metadata.boolField("neighbor_cache_ready", false);
        }
        return metadata.finish();
    }

    void runSessionLoop() {
        SessionState state;
        string line;
        while (std::getline(cin, line)) {
            const string trimmedLine = trim(line);
            if (trimmedLine.empty()) continue;

            string requestId;
            try {
                const auto request = FlatJsonParser(trimmedLine).parseObject();
                requestId = optionalString(request, "request_id", "");
                const string action = requireString(request, "action");

                if (action == "shutdown") {
                    emitComplete(requestId, "shutdown", "后端会话已关闭");
                    return;
                }

                if (action == "get_status") {
                    emitComplete(requestId, "status", "已返回当前会话状态", {}, "", buildDatasetMetadataJson(state));
                    continue;
                }

                if (action == "cancel_task") {
                    emitComplete(requestId, "analysis", "当前版本不支持异步中断，建议前端重建会话以取消任务");
                    continue;
                }

                if (action == "load_dataset") {
                    const string inputFile = requireString(request, "input_file");
                    const int threads = max(1, optionalInt(request, "threads",
                                                           static_cast<int>(Graph::defaultThreadCount())));

                    emitProgress(requestId, "csv_parse", 0.0, "开始加载数据集...");
                    CSVReader reader(inputFile, static_cast<unsigned int>(threads));
                    Graph graph = reader.readCSV([&](const string &message) {
                        double progress = 0.12;
                        if (message.find("CSV 解析完成") != string::npos) progress = 0.36;
                        else if (message.find("并行构建局部图") != string::npos) progress = 0.52;
                        else if (message.find("图模型构建完成") != string::npos) progress = 0.72;
                        emitProgress(
                            requestId,
                            message.find("图模型构建") != string::npos ? "graph_build" : "csv_parse",
                            progress,
                            message
                        );
                    });

                    state.graph = move(graph);
                    state.inputFile = inputFile;
                    state.inputMtime = lastWriteTick(inputFile);
                    state.threads = static_cast<unsigned int>(threads);
                    state.recordCount = reader.getTotalLines();
                    state.clearCaches();

                    emitProgress(requestId, "index_warmup", 0.75, "开始预热图索引与邻居缓存...");
                    warmNeighbors(state, state.threads, requestId);
                    emitProgress(requestId, "index_warmup", 0.97, "索引预热完成");

                    emitComplete(requestId, "index_warmup", "数据集已加载完成", {}, "", buildDatasetMetadataJson(state));
                    continue;
                }

                if (action == "run_task" || action == "export_graph_json") {
                    if (!state.loaded()) {
                        throw runtime_error("当前会话尚未加载数据集");
                    }
                    ParsedArgs args = parseTaskRequest(request, state);
                    const Graph &graph = state.requireGraph();

                    const auto progressCallback = [&](const string &message) {
                        string phase = "analysis";
                        double progress = 0.5;
                        if (message.find("导出") != string::npos || message.find("JSON") != string::npos) {
                            phase = "json_export";
                            progress = 0.85;
                        } else if (message.find("邻居分析") != string::npos) {
                            phase = "analysis";
                            progress = 0.35;
                        } else if (message.find("完成") != string::npos) {
                            progress = 0.95;
                        }
                        emitProgress(requestId, phase, progress, message);
                    };

                    emitProgress(requestId, "analysis", 0.0, "开始执行任务: " + args.task);
                    TaskRunResult result = runTask(graph, args, &state, progressCallback);
                    const string finalPhase = result.resultPath.empty() ? "analysis" : "json_export";
                    emitComplete(requestId, finalPhase, "任务执行完成", result.lines, result.resultPath);
                    continue;
                }

                emitError(requestId, "protocol", "未知 action: " + action);
            } catch (const exception &exc) {
                emitError(requestId, "protocol", exc.what());
            }
        }
    }
}

void printUsage(const char *progName) {
    cerr << "用法:\n"
            << "  " << progName << " --session\n"
            << "  " << progName << " --input <file> --task <task> [选项]\n"
            << "任务:\n"
            << "  full-graph                        导出全网拓扑JSON\n"
            << "  subgraph                          导出以目标IP为中心的子图JSON\n"
            << "  flow-sort                         节点流量排序\n"
            << "  min-congestion                    最小拥塞路径\n"
            << "  min-hop                           最小跳数路径\n"
            << "  min-risk                          最小风险路径\n"
            << "  compare-paths                     比较不同策略下的路径\n"
            << "  port-scan                         检测端口扫描攻击者\n"
            << "  ddos-target                       检测DDoS攻击目标\n"
            << "  star-structures                   查找星型结构\n"
            << "  custom-rule                       自定义规则检测\n"
            << "选项:\n"
            << "  --session                         以 GUI 会话模式启动，使用 JSON 行协议通信\n"
            << "  --output-json <file>              输出JSON图文件（可选）\n"
            << "  --target <ip>                     目标IP（用于子图）\n"
            << "  --src <ip>                        源IP（用于路径）\n"
            << "  --dst <ip>                        目的IP（用于路径）\n"
            << "  --threshold <num>                 阈值（端口扫描、DDoS、星型结构）\n"
            << "  --sort-type <type>                排序类型：total / https / outratio\n"
            << "  --ratio-threshold <num>           出流量占比阈值\n"
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
            << "  --rule-max-traffic <num>          自定义规则：最大流量阈值（可选）\n"
            << "  --help                            显示此帮助\n";
}

int main(const int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    try {
        if (argc >= 2 && string(argv[1]) == "--session") {
            runSessionLoop();
            return 0;
        }

        ParsedArgs args = parseArguments(argc, argv);
        validateArguments(args, true);
        if (args.hasCIDR && args.hasStartEnd) {
            cerr << "警告: 同时提供了 CIDR 和起止IP，将优先使用 CIDR\n";
        }

        auto printProgress = [](const string &message) {
            cout << message << '\n';
        };

        CSVReader reader(args.inputFile, args.threads);
        Graph graph = reader.readCSV(printProgress);
        TaskRunResult result = runTask(graph, args, nullptr, printProgress);
        for (const auto &line: result.lines) {
            cout << line << '\n';
        }
        return 0;
    } catch (const exception &exc) {
        cerr << "错误: " << exc.what() << endl;
        return 1;
    }
}
