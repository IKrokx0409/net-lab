#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include "utils.h" 
#include "config.h"
#include "buf.h"

#include <stdio.h>
#include <string.h>

static const uint8_t ETHERNET_BROADCAST_ADDR[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,                                           
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    // Step 1: 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));
    
    // Step 2: 填写ARP报头
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    
    // 使用模板填充固定字段
    pkt->hw_type16 = arp_init_pkt.hw_type16;
    pkt->pro_type16 = arp_init_pkt.pro_type16;
    pkt->hw_len = arp_init_pkt.hw_len;
    pkt->pro_len = arp_init_pkt.pro_len;

    // Step 3: 设置操作类型
    pkt->opcode16 = swap16(ARP_REQUEST);

    // 填写发送方的运行时地址
    memcpy(pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(pkt->sender_ip, net_if_ip, NET_IP_LEN);

    // 填写目标方
    memset(pkt->target_mac, 0, NET_MAC_LEN); // 请求时目标MAC为全0
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);

    // Step 4: 发送 ARP 报文
    ethernet_out(&txbuf, (uint8_t *)ETHERNET_BROADCAST_ADDR, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    // Step 1: 初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // Step 2: 填写 ARP 报头
    arp_pkt_t *pkt = (arp_pkt_t *)txbuf.data;
    
    // 使用模板填充固定字段
    pkt->hw_type16 = arp_init_pkt.hw_type16;
    pkt->pro_type16 = arp_init_pkt.pro_type16;
    pkt->hw_len = arp_init_pkt.hw_len;
    pkt->pro_len = arp_init_pkt.pro_len;

    // 设置操作类型
    pkt->opcode16 = swap16(ARP_REPLY); 

    // 填写发送方 (本机)
    memcpy(pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(pkt->sender_ip, net_if_ip, NET_IP_LEN);

    // 填写目标方
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);

    // Step 3: 发送 ARP 报文 (单播)
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }
    
    arp_pkt_t *pkt = (arp_pkt_t *)buf->data;

    // Step 2: 报头检查
    if (pkt->hw_type16 != arp_init_pkt.hw_type16 ||  // 硬件类型
        pkt->pro_type16 != arp_init_pkt.pro_type16 || // 协议类型
        pkt->hw_len != NET_MAC_LEN ||                 // 硬件地址长
        pkt->pro_len != NET_IP_LEN) {                 // 协议地址长
        return;
    }

    uint16_t opcode = swap16(pkt->opcode16);

    // Step 3: 更新 ARP 表项 (将发送方的 IP-MAC 映射存入/更新)
    map_set(&arp_table, pkt->sender_ip, pkt->sender_mac);

    // Step 4: 查看缓存情况
    buf_t *cached_buf = (buf_t *)map_get(&arp_buf, pkt->sender_ip);

    // 有缓存情况
    if (cached_buf) {
        // 将缓存的 IP 包发送出去，目标 MAC 是刚收到的 ARP 包的源 MAC
        ethernet_out(cached_buf, pkt->sender_mac, NET_PROTOCOL_IP);
        
        // 删除缓存
        map_delete(&arp_buf, pkt->sender_ip);
    }
    // 无缓存情况
    else {
        // 检查这是不是一个针对本机的 ARP 请求
        if (opcode == ARP_REQUEST && memcmp(pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            arp_resp(pkt->sender_ip, pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // Step 1: 查找 ARP 表
    uint8_t *mac = (uint8_t *)map_get(&arp_table, ip);

    // Step 2: 找到对应 MAC 地址
    if (mac) {
        // 找到了，直接发给以太网层
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } 
    // Step 3: 未找到对应 MAC 地址
    else {
        // 检查是否已经有包在等待该 IP 的 ARP 响应
        if (map_get(&arp_buf, ip)) {
            return;
        } else {
            // 没有包在等待
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}