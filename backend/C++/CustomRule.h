//
// Created by Na_Bian on 2026/3/5.
//


# ifndef NETWORKANALYZER_CUSTOM_RULE_H
# define NETWORKANALYZER_CUSTOM_RULE_H

# include "Graph.h"
# include <limits>
# include <utility>

enum class RuleType { DENY, ALLOW };

//违规记录类，包含源IP地址、目的IP地址、端口号和违规原因
class ViolationRecord {
    IPAddress src;
    IPAddress dst;
    uint8_t protocol;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string reason;

public:
    ViolationRecord(const IPAddress &src, const IPAddress &dst, const uint8_t protocol, const uint16_t srcPort,
                    const uint16_t dstPort, std::string reason) : src(src), dst(dst), protocol(protocol),
                                                                  srcPort(srcPort), dstPort(dstPort),
                                                                  reason(std::move(reason)) {
    }

    //Getters
    [[nodiscard]] IPAddress getSrcIP() const { return src; }

    [[nodiscard]] IPAddress getDstIP() const { return dst; }

    [[nodiscard]] uint8_t getProtocol() const { return protocol; }

    [[nodiscard]] uint16_t getSrcPort() const { return srcPort; }

    [[nodiscard]] uint16_t getDstPort() const { return dstPort; }

    [[nodiscard]] std::string getReason() const { return reason; }

    //重载<运算符，使ViolationRecord对象可以在set中进行比较和排序
    bool operator<(const ViolationRecord &other) const {
        if (src != other.src) {
            return src.getIP() < other.src.getIP(); //首先比较源IP地址
        }
        if (dst != other.dst) {
            return dst.getIP() < other.dst.getIP(); //如果源IP地址相同，比较目的IP地址
        }
        if (protocol != other.protocol) {
            return protocol < other.protocol; //如果目的IP地址也相同，比较协议类型
        }
        if (srcPort != other.srcPort) {
            return srcPort < other.srcPort; //如果目的IP地址也相同，比较源端口号
        }
        if (dstPort != other.dstPort) {
            return dstPort < other.dstPort; //如果源端口号也相同，比较目的端口号
        }
        return reason < other.reason; //如果端口号也相同，比较违规原因字符串
    }
};

//基于自定义规则的异常检测类，用户可以在此类中定义自己的异常检测规则和算法
class CustomRule {
    Graph graph; //网络拓扑图对象
    IPAddress targetIP; // 待检测的目标IP地址
    std::pair<IPAddress, IPAddress> IPRange; // IP地址范围，包含起始IP和结束IP
    uint8_t protocol; // 协议号，0表示所有协议
    uint16_t srcPort; // 源端口号，0表示所有端口
    uint16_t dstPort; // 目的端口号，0表示所有端口
    RuleType type; // IP连接规则类型，DENY表示禁止连接，ALLOW表示允许连接
    long long maxTraffic; // 最大流量阈值

    //静态辅助函数parseCIDR用于解析CIDR格式的IP地址范围字符串，并返回起始IP和结束IP的元组
    static std::pair<IPAddress, IPAddress> parseCIDR(const std::string &cidr) {
        // 查找 '/' 分隔符
        const size_t slashPos = cidr.find('/');
        if (slashPos == std::string::npos) {
            throw std::invalid_argument("无效的CIDR格式: " + cidr); // 如果没有找到 '/'，抛出异常
        }

        //分割IP地址和掩码长度
        const std::string ipPart = cidr.substr(0, slashPos); // 获取CIDR字符串中的IP地址部分
        const std::string maskPart = cidr.substr(slashPos + 1); // 获取CIDR字符串中的掩码长度部分

        //将IP地址转换为整数
        const uint32_t ip = IPAddress(ipPart.c_str()).getIP();

        //解析掩码长度
        const int maskLength = stoi(maskPart); // 将掩码长度字符串转换为整数
        if (maskLength < 0 || maskLength > 32) {
            throw std::invalid_argument("无效的掩码长度: " + maskPart); // 如果掩码长度不在0到32之间，抛出异常
        }

        //计算网络地址和广播地址
        const uint32_t mask = maskLength == 0 ? 0 : ~static_cast<uint32_t>(0) << (32 - maskLength); // 计算子网掩码
        const uint32_t network = ip & mask; // 网络地址 = IP地址 & 子网掩码
        const uint32_t broadcast = network | ~mask; // 广播地址 = 网络地址 | 子网掩码的反码

        return {IPAddress(network), IPAddress(broadcast)}; // 返回起始IP和结束IP的元组
    }

public:
    //构造函数，初始化自定义规则的参数
    //默认参数：端口号为0（表示所有端口），最大流量阈值为long long的最大值，规则类型为DENY
    CustomRule(Graph graph, const IPAddress &targetIP, const IPAddress &start, const IPAddress &end,
               const uint8_t protocol = 0, const uint16_t srcPort = 0, const uint16_t dstPort = 0,
               const RuleType type = RuleType::DENY,
               const long long maxTraffic = (std::numeric_limits<long long>::max)()) : graph(std::move(graph)),
        targetIP(targetIP), IPRange({start, end}), protocol(protocol),
        srcPort(srcPort), dstPort(dstPort), type(type), maxTraffic(maxTraffic) {
        if (start.getIP() > end.getIP()) {
            // 如果起始IP地址大于结束IP地址，抛出异常
            throw std::invalid_argument("无效的IP范围: " + start.toString() + " - " + end.toString());
        }
    }

    //重载构造函数：使用CIDR字符串指定IP范围
    CustomRule(const Graph &graph, const IPAddress &targetIP, const std::string &cidr, const uint8_t protocol = 0,
               const uint16_t srcPort = 0, const uint16_t dstPort = 0, const RuleType type = RuleType::DENY,
               const long long maxTraffic = (std::numeric_limits<long long>::max)()) : CustomRule(graph, targetIP,
        parseCIDR(cidr).first, // 起始 IP
        parseCIDR(cidr).second, // 结束 IP
        protocol, srcPort, dstPort, type, maxTraffic) {
    }

    //函数checkViolation用于检查当前网络记录是否违反了自定义规则
    [[nodiscard]] std::string checkViolation(const IPAddress &other, const uint8_t recordProtocol,
                                             const uint16_t recordSrcPort, const uint16_t recordDstPort,
                                             const long long traffic) const {
        std::string reason; //用于存储违规原因的字符串
        //RuleType为DENY
        if (type == RuleType::DENY) {
            //检查记录中的IP地址是否在规则禁止的范围内
            if (other.getIP() >= IPRange.first.getIP() && other.getIP() <= IPRange.second.getIP()) {
                reason += "与" + other.toString() + "的通信违反IP地址范围规则;";
            }
        } else {
            //RuleType为ALLOW，检查记录中的IP地址是否在规则允许的范围外
            if (other.getIP() < IPRange.first.getIP() || other.getIP() > IPRange.second.getIP()) {
                reason += "与" + other.toString() + "的通信违反IP地址范围规则;";
            }
        }
        //检查记录中的协议类型是否匹配规则定义的协议类型
        if (protocol != 0 && recordProtocol == protocol) {
            if (type == RuleType::DENY) {
                reason += "协议类型" + std::to_string(protocol) + "违反规则;";
            }
        }
        //检查记录中的源端口号是否匹配规则定义的端口号
        if (srcPort != 0 && recordSrcPort == srcPort) {
            if (type == RuleType::DENY) {
                reason += "源端口" + std::to_string(srcPort) + "违反规则;";
            }
        }
        //检查记录中的目的端口号是否匹配规则定义的端口号
        if (dstPort != 0 && recordDstPort == dstPort) {
            if (type == RuleType::DENY) {
                reason += "目的端口" + std::to_string(dstPort) + "违反规则;";
            }
        }
        //检查记录中的流量是否超过规则定义的最大流量阈值
        if (traffic > maxTraffic) {
            reason += "与" + other.toString() + "的通信流量为" + std::to_string(traffic) +
                    " bytes，超过了最大流量阈值" + std::to_string(maxTraffic) + " bytes.";
        }
        if (reason.empty()) {
            return ""; //如果没有违规原因，返回空字符串
        }
        //去掉末尾可能存在的分号
        if (reason.back() == ';') {
            reason.pop_back();
        }
        return reason; //返回违规原因字符串，如果没有违规则返回空字符串
    }

    //函数ViolationRecords用于根据自定义规则检查图中的网络记录，并返回所有违反规则的记录列表
    std::set<ViolationRecord> ViolationRecords() {
        if (const int targetIndex = graph.findVertexIndex(targetIP); targetIndex == -1) {
            throw std::runtime_error("找不到目标IP: " + targetIP.toString()); // 如果在图中找不到目标IP地址，抛出异常
        }

        //分析图中节点targetIP的邻居信息，返回一个包含邻居索引和邻居信息的字典
        std::unordered_map<int, NeighborInfo> neighbors = graph.analyzeNeighbors(targetIP);

        std::set<ViolationRecord> violations; //创建一个集合用于存储违反规则的记录

        //遍历目标IP地址所有的邻居信息，检查每个邻居节点是否违反了自定义规则
        for (const auto &[neighborIndex, info]: neighbors) {
            const IPAddress &neighborIP = graph.getVertexIP(neighborIndex); //获取邻居节点的IP地址
            //遍历目标IP地址与邻居节点之间的所有通信记录，检查每条记录是否违反了自定义规则
            for (const auto &[recordProtocol, recordSrcPort, recordDstPort]: info.ports) {
                if (std::string reason = checkViolation(
                        neighborIP, recordProtocol, recordSrcPort, recordDstPort, info.InData + info.OutData);
                    !reason.empty()) {
                    //如果邻居节点违反了自定义规则，则将其添加到违规记录列表中
                    violations.insert({targetIP, neighborIP, recordProtocol, recordSrcPort, recordDstPort, reason});
                }
            }
        }
        return violations; //返回违反规则的记录列表
    }
};


# endif //NETWORKANALYZER_CUSTOM_RULE_H
