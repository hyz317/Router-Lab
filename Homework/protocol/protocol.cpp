#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

void printIP(uint32_t ip);

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  unsigned int ipLen = (packet[0] & 0xF) * 4;
  unsigned int udpLen = ((unsigned int)packet[ipLen + 4] << 8) + packet[ipLen + 5];

  unsigned int command = packet[ipLen + 8];
  unsigned int family = ((unsigned int)packet[ipLen + 12] << 8) + packet[ipLen + 13];
  unsigned int version = packet[ipLen + 9];
  unsigned int zero = ((unsigned int)packet[ipLen + 10] << 8) + packet[ipLen + 11];

  unsigned int num = (udpLen - 12) / 20;
  unsigned int begin = ipLen + 12;

  if ((packet[2] << 8) + packet[3] > len)
    return false;
  if (version != 2 || zero != 0)
    return false;
  if (!((command == 2 && family == 2) || (command == 1 && family == 0)))
    return false;

  output->numEntries = num;
  output->command = command;
  for (int i = 0; i < num; i++) {
    unsigned int metric = ((unsigned int)packet[begin + 16] << 24) + ((unsigned int)packet[begin + 17] << 16) + ((unsigned int)packet[begin + 18] << 8) + (unsigned int)packet[begin + 19];
    unsigned int netmask = ((unsigned int)packet[begin + 8] << 24) + ((unsigned int)packet[begin + 9] << 16) + ((unsigned int)packet[begin + 10] << 8) + (unsigned int)packet[begin + 11];
    netmask = ~netmask + 1;
    if (metric < 1 || metric > 16)
      return false;
    if ((netmask & (netmask - 1)) != 0)
      return false;
    output->entries[i].addr = ((unsigned int)packet[begin + 7] << 24) + ((unsigned int)packet[begin + 6] << 16) + ((unsigned int)packet[begin + 5] << 8) + (unsigned int)packet[begin + 4];
    output->entries[i].mask = ((unsigned int)packet[begin + 11] << 24) + ((unsigned int)packet[begin + 10] << 16) + ((unsigned int)packet[begin + 9] << 8) + (unsigned int)packet[begin + 8];
    output->entries[i].metric = ((unsigned int)packet[begin + 19] << 24) + ((unsigned int)packet[begin + 18] << 16) + ((unsigned int)packet[begin + 17] << 8) + (unsigned int)packet[begin + 16];
    output->entries[i].nexthop = ((unsigned int)packet[begin + 15] << 24) + ((unsigned int)packet[begin + 14] << 16) + ((unsigned int)packet[begin + 13] << 8) + (unsigned int)packet[begin + 12];

    begin += 20;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  unsigned int len = rip->numEntries * 20 + 4;
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = buffer[3] = 0;
  unsigned int begin = 4;
  for (int i = 0; i < rip->numEntries; i++) {
    buffer[begin] = 0;
    if (rip->command == 1)
      buffer[begin + 1] = 0;
    else
      buffer[begin + 1] = 2;
    buffer[begin + 2] = buffer[begin + 3] = 0;

    buffer[begin + 4] = rip->entries[i].addr & 0x000000ff;
    buffer[begin + 5] = (rip->entries[i].addr >> 8) & 0x000000ff;
    buffer[begin + 6] = (rip->entries[i].addr >> 16) & 0x000000ff;
    buffer[begin + 7] = (rip->entries[i].addr >> 24) & 0x000000ff;
    printIP(rip->entries[i].addr);

    buffer[begin + 8] = rip->entries[i].mask & 0x000000ff;
    buffer[begin + 9] = (rip->entries[i].mask >> 8) & 0x000000ff;
    buffer[begin + 10] = (rip->entries[i].mask >> 16) & 0x000000ff;
    buffer[begin + 11] = (rip->entries[i].mask >> 24) & 0x000000ff;
    printIP(rip->entries[i].mask);

    buffer[begin + 12] = rip->entries[i].nexthop & 0x000000ff;
    buffer[begin + 13] = (rip->entries[i].nexthop >> 8) & 0x000000ff;
    buffer[begin + 14] = (rip->entries[i].nexthop >> 16) & 0x000000ff;
    buffer[begin + 15] = (rip->entries[i].nexthop >> 24) & 0x000000ff;
    printIP(rip->entries[i].nexthop);

    buffer[begin + 16] = rip->entries[i].metric & 0x000000ff;
    buffer[begin + 17] = (rip->entries[i].metric >> 8) & 0x000000ff;
    buffer[begin + 18] = (rip->entries[i].metric >> 16) & 0x000000ff;
    buffer[begin + 19] = (rip->entries[i].metric >> 24) & 0x000000ff;

    begin += 20;
  }
  return len;
}
