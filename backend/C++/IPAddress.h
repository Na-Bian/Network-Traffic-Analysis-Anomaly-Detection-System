//
// Created by Na_Bian on 2026/3/7.
//

# ifndef NETWORKANALYZER_IPADDRESS_H
# define NETWORKANALYZER_IPADDRESS_H

# include <cstdint>
# include <string>
# include <stdexcept>
# include <sstream>


//IP地址类，管理IP地址的转换和存储
class IPAddress {
    uint32_t IP; // 32位整数形式的IP地址

    // 辅助函数，解析点分十进制字符串，返回主机字节序整数
    static uint32_t parseIPv4(const std::string &ipStr) {
        std::istringstream iss(ipStr); // 使用输入字符串流解析IP地址字符串
        int a = -1, b = -1, c = -1, d = -1;
        char ch1, ch2, ch3;
        iss >> a >> ch1 >> b >> ch2 >> c >> ch3 >> d; //从字符串中提取四个整数和三个点分隔符
        if (!iss.eof() || iss.fail() || ch1 != '.' || ch2 != '.' || ch3 != '.') {
            throw std::invalid_argument("错误的IP地址格式: " + ipStr);
        }
        if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
            throw std::invalid_argument("IP地址字段超出范围: " + ipStr);
        }
        return static_cast<uint32_t>(a) << 24 |
               static_cast<uint32_t>(b) << 16 |
               static_cast<uint32_t>(c) << 8 |
               static_cast<uint32_t>(d);
    }

public:
    // 构造函数，接受点分十进制字符串形式的IP地址
    IPAddress(const char *ipStr) : IP(parseIPv4(ipStr)) {
    }

    IPAddress(const std::string &ipStr) : IP(parseIPv4(ipStr)) {
    }

    // 重载构造函数，接受IP地址的主机字节序整数形式
    IPAddress(const uint32_t ip) : IP(ip) {
    }

    //获取IP地址的整数形式
    [[nodiscard]] uint32_t getIP() const { return IP; }

    //获取IP地址的点分十进制字符串形式
    [[nodiscard]] std::string toString() const {
        const uint32_t ip = IP;
        return std::to_string(ip >> 24 & 0xFF) + "." +
               std::to_string(ip >> 16 & 0xFF) + "." +
               std::to_string(ip >> 8 & 0xFF) + "." +
               std::to_string(ip & 0xFF);
    }

    //重载==运算符，比较两个IPAddress是否相等
    bool operator==(const IPAddress &other) const { return IP == other.IP; }

    bool operator==(const std::string &other) const {
        try {
            return IP == parseIPv4(other);
        } catch (const std::invalid_argument &) {
            return false; // 如果字符串格式错误，返回false
        }
    }

    bool operator!=(const IPAddress &other) const {
        return !(*this == other);
    }

    //重载<运算符，按照整数形式的IP地址进行比较
    bool operator<(const IPAddress &other) const {
        return this->IP < other.IP;
    }
};


# endif //NETWORKANALYZER_IPADDRESS_H
