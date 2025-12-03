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
    // 我们需要构建一个新的 buffer 来发送响应
    // 响应包的大小与请求包完全一致（Header + Data）
    buf_t txbuf;
    buf_init(&txbuf, req_buf->len);

    // 将请求报文的所有内容（包括ICMP头和Payload）拷贝到发送缓冲区
    // Echo Reply (Type 0) 的 ID、Sequence Number 和 Data 字段必须与 Echo Request (Type 8) 一致
    // 所以直接拷贝最方便，之后只需修改 Type, Code 和 Checksum
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    // 获取 ICMP 报头指针
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;

    // 修改为回显应答 (Echo Reply)
    icmp_hdr->type = ICMP_TYPE_ECHO_REPLY; // Type = 0
    icmp_hdr->code = 0;                    // Code = 0

    // Step 2: 填写校验和
    // 计算校验和之前，必须先将 checksum 字段置 0
    icmp_hdr->checksum16 = 0;
    // ICMP 校验和覆盖整个 ICMP 报文（首部 + 数据），算法与 IP 校验和一致
    icmp_hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);

    // Step 3: 发送数据报
    // 调用 IP 层发送函数，协议类型为 ICMP
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
    // 检查接收到的数据包长度是否小于 ICMP 头部长度 (8字节)
    if (buf->len < sizeof(icmp_hdr_t)) {
        return; // 数据包不完整，丢弃
    }

    // 获取 ICMP 报头
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)buf->data;

    // Step 2: 查看 ICMP 类型
    // 如果是回显请求 (Echo Request, Type = 8)
    if (icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step 3: 回送回显应答
        icmp_resp(buf, src_ip);
    }
    
    // 其他类型的 ICMP 报文目前不需要处理
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包 (注意：在 ip_in 中已恢复了 IP 报头)
 * @param src_ip 源ip地址 (导致错误的发送方 IP)
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // 根据 RFC 792，ICMP 差错报文的数据部分包含：
    // 1. IP 首部
    // 2. IP 数据报的前 8 个字节
    
    // Step 1: 初始化并填写报头
    buf_t txbuf;
    // 计算总长度 = ICMP首部长度(8) + IP首部长度(20) + IP载荷前8字节
    // 注意：这里假设 IP 首部没有 Option 字段，长度固定为 sizeof(ip_hdr_t)
    size_t copy_len = sizeof(ip_hdr_t) + 8;
    buf_init(&txbuf, sizeof(icmp_hdr_t) + copy_len);

    // 填写 ICMP 报头
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)txbuf.data;
    icmp_hdr->type = ICMP_TYPE_UNREACH; // Type = 3 (Destination Unreachable)
    icmp_hdr->code = code;              // 具体错误代码 (协议不可达或端口不可达)
    icmp_hdr->id16 = 0;                 // 差错报文中未使用，置0
    icmp_hdr->seq16 = 0;                // 差错报文中未使用，置0
    icmp_hdr->checksum16 = 0;           // 先置0以便计算

    // Step 2: 填写数据与校验和
    // 将收到的 IP 包的 IP 首部 + 前 8 字节数据 拷贝到 ICMP 报头之后
    // txbuf.data 指向 ICMP 报头，偏移 sizeof(icmp_hdr_t) 后即为数据区
    memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data, copy_len);

    // 计算校验和 (覆盖整个 ICMP 报文)
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