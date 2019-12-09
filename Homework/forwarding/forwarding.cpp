#include <stdint.h>
#include <stdlib.h>


bool validateIPChecksum(uint8_t *packet, size_t len);

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  if (!validateIPChecksum(packet, len))
    return false;
  packet[8]--;
  validateIPChecksum(packet, len);
  return true;
}

// bool validateIPChecksum(uint8_t *packet, size_t len) {
//   unsigned int checksumInPacket = ((unsigned long)packet[10] << 8) + (unsigned long)packet[11];
//   uint8_t packet_10 = packet[10], packet_11 = packet[11]; 
//   packet[10] = packet[11] = 0;
//   int length = (packet[0] & 0xf) * 4;
//   unsigned int checkSum = 0;
//   for (int i = 0; i < length; i += 2) {
//     checkSum += ((unsigned long)packet[i] << 8) + (unsigned long)packet[i + 1];
//   }
//   while (checkSum >> 16) {
//     checkSum = (checkSum >> 16) + (checkSum & 0xFFFF);
//   }
//   unsigned short realCheckSum = (unsigned short)~checkSum;
//   packet[10] = realCheckSum >> 8;
//   packet[11] = realCheckSum & 0xFFFF;
//   if (realCheckSum == checksumInPacket) {
//     return true;
//   }
//   else
//     return false;
// }
