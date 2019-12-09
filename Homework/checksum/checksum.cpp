#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  unsigned int checksumInPacket = ((unsigned long)packet[10] << 8) + (unsigned long)packet[11];
  packet[10] = packet[11] = 0;
  int length = (packet[0] & 0xf) * 4;
  // printf("%d\n", length);
  // printf("%04x\n", checksumInPacket);
  // for (int i = 0; i < 20; i++) {
  //   printf("%02x ", packet[i]);
  // }

  unsigned int checkSum = 0;
  for (int i = 0; i < length; i += 2) {
    checkSum += ((unsigned long)packet[i] << 8) + (unsigned long)packet[i + 1];
  }
  // printf("%05x\n", checkSum);
  while (checkSum >> 16) {
    checkSum = (checkSum >> 16) + (checkSum & 0xFFFF);
  }
  unsigned short realCheckSum = (unsigned short)~checkSum;
  // printf("%04x\n", (unsigned short)~checkSum);
  packet[10] = realCheckSum >> 8;
  packet[11] = realCheckSum & 0xFFFF;
  if (realCheckSum == checksumInPacket)
    return true;
  else
    return false;
}
