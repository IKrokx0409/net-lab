#include "icmp.h"
#include "ip.h"
#include "net.h"
#include <string.h> // 需要用到 memcpy

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包 (去除了IP首部，data指向ICMP首部)
 * @param src_ip 源ip地址 (请求方的IP，即我们回复的目标IP)
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step 1: 初始化并封装数据
    buf_t txbuf;
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    // 获取 ICMP 报头指针
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;

    // 修改为回显应答 (Echo Reply)
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY; // Type = 0
    icmp_hdr->code = 0;                    // Code = 0

    // Step 2: 填写校验和
    icmp_hdr->checksum16 = 0;
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // Step 3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包 (已去除IP首部)
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step 1: 报头检测
    if (buf->len < sizeof(icmp_hdr_t)) {
        return; // 数据包不完整，丢弃
    }

    // 获取 ICMP 报头
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;

    // Step 2: 查看 ICMP 类型
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step 3: 回送回显应答
        icmp_resp(buf, src_ip);
    }
    
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包 (注意：在 ip_in 中已恢复了 IP 报头)
 * @param src_ip 源ip地址 (导致错误的发送方 IP)
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step 1: 初始化并填写报头
    buf_t txbuf;
    size_t copy_len = sizeof(ip_hdr_t) + 8;
    buf_init(&txbuf, sizeof(icmp_hdr_t) + copy_len);

    // 填写 ICMP 报头
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH;
    icmp_hdr->code = code;              // 具体错误代码
    icmp_hdr->id16 = 0;                 // 差错报文中未使用，置0
    icmp_hdr->seq16 = 0;                // 差错报文中未使用，置0
    icmp_hdr->checksum16 = 0;           // 先置0以便计算

    // Step 2: 填写数据与校验和
    memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data, copy_len);

    // 计算校验和
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // Step 3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}