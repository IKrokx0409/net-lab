#include "utils.h"

#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 *
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip) {
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 *
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac) {
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 *
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp) {
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
}

/**
 * @brief ip前缀匹配
 *
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb) {
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++) {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++) {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 *
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len) {
    uint32_t sum = 0;
    uint16_t *p = data;
    
    // Step 1: 按 16 位分组相加
    // 这里的循环次数是 len / 2，因为每次处理 2 个字节
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }

    // Step 2: 处理剩余 8 位
    // 如果长度是奇数，最后一个字节被视为高 8 位，低 8 位补 0（或者直接作为单独的一个字节加进去，取决于大小端，网络序通常直接转换）
    // 注意：这里需要根据具体的实验环境强制转换，通常处理为：
    if (len > 0) {
        sum += *(uint8_t *)p;
    }

    // Step 3: 循环处理高 16 位（进位处理）
    // 将 32 位的和折叠成 16 位
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Step 4: 取反得到校验和
    return ~((uint16_t)sum);
}

#pragma pack(1)
typedef struct peso_hdr {
    uint8_t src_ip[4];     // 源IP地址
    uint8_t dst_ip[4];     // 目的IP地址
    uint8_t placeholder;   // 必须置0,用于填充对齐
    uint8_t protocol;      // 协议号
    uint16_t total_len16;  // 整个数据包的长度
} peso_hdr_t;
#pragma pack()

/**
 * @brief 计算传输层协议（如TCP/UDP）的校验和
 *
 * @param protocol  传输层协议号（如NET_PROTOCOL_UDP、NET_PROTOCOL_TCP）
 * @param buf       待计算的数据包缓冲区
 * @param src_ip    源IP地址
 * @param dst_ip    目的IP地址
 * @return uint16_t 计算得到的16位校验和
 */
uint16_t transport_checksum(uint8_t protocol, buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip) {
    // TO-DO
    // Step 1: 增加 UDP 伪头部
    // 伪头部大小为 12 字节 (sizeof(peso_hdr_t))
    // buf_add_header 会调整 buf->data 指针向前移动，留出空间
    if (buf_add_header(buf, sizeof(peso_hdr_t)) != 0) {
        return 0; // 空间不足等错误处理
    }

    // Step 2: 暂存 IP 头部 (也就是刚刚被 buf_add_header 覆盖掉的内存区域)
    // 实际上 buf_add_header 只是移动了指针，前面的数据（原来的IP头末尾）变成了我们要写伪头的地方
    // 为了不破坏之前层的数据（虽然在这里通常是被剥离的IP头），我们先备份这块内存
    peso_hdr_t backup_hdr;
    memcpy(&backup_hdr, buf->data, sizeof(peso_hdr_t));

    // Step 3: 填写 UDP 伪头部字段
    // 伪头部结构体定义在 utils.c 开头 (peso_hdr_t)
    peso_hdr_t *peso = (peso_hdr_t *)buf->data;
    
    memcpy(peso->src_ip, src_ip, NET_IP_LEN);
    memcpy(peso->dst_ip, dst_ip, NET_IP_LEN);
    peso->placeholder = 0;           // 必须置0
    peso->protocol = protocol;       // 协议号 (UDP为17)
    // UDP长度 = 伪头部之后的总长度 (即 UDP首部 + UDP数据)
    // 注意：buf->len 现在包含了伪头部，所以要减去 sizeof(peso_hdr_t)
    peso->total_len16 = swap16(buf->len - sizeof(peso_hdr_t));

    // Step 4: 计算 UDP 校验和
    // 校验和覆盖：伪头部 + UDP首部 + UDP数据
    uint16_t checksum = checksum16((uint16_t *)buf->data, buf->len);

    // Step 5: 恢复 IP 头部
    // 将备份的数据写回，恢复现场
    memcpy(buf->data, &backup_hdr, sizeof(peso_hdr_t));

    // Step 6: 去掉 UDP 伪头部
    // 将 buf->data 指针移回原来的位置 (指向 UDP 首部)
    buf_remove_header(buf, sizeof(peso_hdr_t));

    // Step 7: 返回校验和值
    return checksum;
}