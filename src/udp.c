#include "udp.h"
#include "ip.h"
#include "icmp.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>

// 引用 config.h 中的本机 IP
extern uint8_t net_if_ip[NET_IP_LEN];

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // Step 1: 包检查
    // 检查数据报长度是否小于 UDP 首部长度
    if (buf->len < sizeof(udp_hdr_t)) {
        return;
    }
    
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;
    // 检查接收到的包长度是否小于 UDP 首部中记录的长度
    if (buf->len < swap16(udp_hdr->total_len16)) {
        return;
    }

    // Step 2: 重新计算校验和
    uint16_t rcv_checksum = udp_hdr->checksum16;
    
    // 如果校验和不为0，则进行验证
    if (rcv_checksum != 0) {
        // 将校验和字段置 0 以重新计算
        udp_hdr->checksum16 = 0;
        
        // 计算校验和：注意这里的源和目的 IP
        // 对于接收包：源是 src_ip (对方)，目的是 net_if_ip (本机)
        uint16_t calc_checksum = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
        
        if (calc_checksum != rcv_checksum) {
            return; // 校验和不匹配，丢弃
        }
        // 恢复校验和字段
        udp_hdr->checksum16 = rcv_checksum;
    }

    // Step 3: 查询处理函数
    uint16_t dst_port = swap16(udp_hdr->dst_port16); // 转换为主机字节序
    
    // 【关键修复】：map_get 只接收2个参数，返回指向 Value 的指针
    // 我们的 Value 类型是 udp_handler_t，所以返回的是 udp_handler_t *
    udp_handler_t *handler_ptr = (udp_handler_t *)map_get(&udp_table, &dst_port);

    // Step 4: 处理未找到处理函数的情况
    if (handler_ptr == NULL) {
        // 端口未打开，发送 ICMP Port Unreachable
        
        // ICMP 差错报文需要包含原始 IP 头部
        // 由于在 ip_in 中已经去除了 IP 头部，这里需要临时加回去
        buf_add_header(buf, sizeof(ip_hdr_t));
        
        // 调用 ICMP 模块发送端口不可达
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    } else {
        // Step 5: 调用处理函数
        // 去掉 UDP 报头，将 payload 交给应用层处理
        uint16_t src_port = swap16(udp_hdr->src_port16);
        
        buf_remove_header(buf, sizeof(udp_hdr_t));
        
        // 解引用指针获取实际的函数指针
        udp_handler_t handler = *handler_ptr;
        if (handler) {
            handler(buf->data, buf->len, src_ip, src_port);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // Step 1: 添加 UDP 报头
    buf_add_header(buf, sizeof(udp_hdr_t));

    // Step 2: 填充 UDP 首部字段
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;
    
    udp_hdr->src_port16 = swap16(src_port);      // 转换为网络字节序
    udp_hdr->dst_port16 = swap16(dst_port);      // 转换为网络字节序
    udp_hdr->total_len16 = swap16(buf->len);     // 包含头部和数据的总长度
    udp_hdr->checksum16 = 0;                     // 先置 0

    // Step 3: 计算并填充校验和
    // 发送包：源是 net_if_ip (本机)，目的是 dst_ip (对方)
    udp_hdr->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);

    // Step 4: 发送 UDP 数据报
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_t txbuf;
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}