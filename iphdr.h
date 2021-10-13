#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    u_int8_t hl_:4;
    u_int8_t ver_:4;
    u_int8_t tos_;
    u_int16_t len_;
    u_int16_t id_;
    u_int16_t off_;
    u_int8_t ttl_;
    u_int8_t pro_;
    u_int16_t sum_;
    Ip sip_;
    Ip tip_;

    Ip sip() { return ntohl(sip_); }
    Ip tip() { return ntohl(tip_); }
};
#pragma pack(pop)