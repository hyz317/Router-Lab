#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

extern void encapRip(RipPacket* resp);
extern void printRouteTable();

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
//                                      0x0103000a};
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};

void printMAC(macaddr_t mac) {
  printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3],
         mac[4], mac[5]);
}

void printIP(in_addr_t ip) {
  printf("%d.%d.%d.%d\n",  ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, ip >> 24);
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i], // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = 1 << 24,
        .timestamp = HAL_GetTicks()
    };
    update(true, entry);
  }

  printRouteTable();

  // macaddr_t dest_mac;
  // HAL_ArpGetMacAddress(0, (in_addr_t)((9 << 24) | 224), dest_mac);
  // printMAC(dest_mac);
  // RipPacket resp;
  // // TODO: fill resp
  // // assemble
  // encapRip(&resp);
  // printf("%u %u\n", resp.numEntries, resp.command);
  // for (int i = 0; i < resp.numEntries; i++) {
  //   printf("%u %u %u %u\n", resp.entries[i].addr, resp.entries[i].mask, resp.entries[i].nexthop, resp.entries[i].metric);
  // }
  // uint32_t res2 = assemble(&resp, &output[20 + 8]);
  // for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
  //   HAL_SendIPPacket(i, packet, res2, dest_mac);
  // }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      // change here
      macaddr_t dest_mac;
      HAL_ArpGetMacAddress(0, (in_addr_t)((9 << 24) | 224), dest_mac);
      printMAC(dest_mac);
      RipPacket resp;
      // TODO: fill resp
      // assemble
      encapRip(&resp);
      uint32_t rip_len = assemble(&resp, &output[20 + 8]);
      // resp.command = 1;
      // resp.numEntries = 1;
      // resp.entries[0].addr = 0;
      // resp.entries[0].mask = 0;
      // resp.entries[0].nexthop = 0;
      // resp.entries[0].metric = 1;
      // uint32_t rip_len = assemble(&resp, &output[20 + 8]);

      output[0] = 0x45;
      output[1] = 0xc0;
      output[2] = ((rip_len + 20 + 8) >> 8);
      output[3] = (rip_len + 20 + 8) & 0xff;
      output[4] = output[5] = 0x00;
      output[6] = 0x40;
      output[7] = 0x00;
      output[8] = 0x04;
      output[9] = 0x11;
      output[10] = output[11] = 0x00;
  
      output[16] = 224;
      output[17] = output[18] = 0;
      output[19] = 9;
      output[20] = 0x02;
      output[21] = 0x08;
      output[22] = 0x02;
      output[23] = 0x08;
      output[24] = ((rip_len + 8) >> 8);
      output[25] = (rip_len + 8) & 0xff;
      printf("%d %d\n", output[24], output[25]);
      output[26] = output[27] = 0;

      for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
        output[12] = addrs[i] & 0xff;
        output[13] = (addrs[i] >> 8) & 0xff;
        output[14] = (addrs[i] >> 16) & 0xff;
        output[15] = (addrs[i] >> 24) & 0xff;
        validateIPChecksum(output, rip_len + 20 + 8);
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, dest_mac);
      }
      // end change
      printf("30s Timer\n");
      // printRouteTable();
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }
    // change here
    printf("Got IP packet of length %d from port %d\n", res, if_index);
    printf("Src MAC: ");
    printMAC(src_mac);
    printf("Dst MAC: ");
    printMAC(dst_mac);
    printf("\nData: ");
    for (int i = 0; i < res; i++) {
      printf("%02X ", packet[i]);
    }
    printf("\n");
    // end change

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian

    // change here
    src_addr = (unsigned int)packet[12] + (packet[13] << 8) + (packet[14] << 16) + (packet[15] << 24);
    dst_addr = (unsigned int)packet[16] + (packet[17] << 8) + (packet[18] << 16) + (packet[19] << 24);
    printf("src addr: ");
    printIP(src_addr);
    printf("\n");
    printf("dst addr: ");
    printIP(dst_addr);
    printf("\n");
    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    if ((dst_addr & 0xe0) == 0xe0) {
      dst_is_me = true;
    }

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          // TODO: fill resp
          // assemble
          encapRip(&resp);
          // IP
          // output[0] = 0x45;
          // ...
          // UDP
          // port = 520
          // output[20] = 0x02;
          // output[21] = 0x08;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          output[0] = 0x45;
          output[1] = 0xc0;
          output[2] = ((rip_len + 20 + 8) >> 8);
          output[3] = (rip_len + 20 + 8) & 0xff;
          output[4] = output[5] = 0x00;
          output[6] = 0x40;
          output[7] = 0x00;
          output[8] = 0x04;
          output[9] = 0x11;
          output[10] = output[11] = 0x00;
          output[12] = src_addr & 0xff;
          output[13] = (src_addr >> 8) & 0xff;
          output[14] = (src_addr >> 16) & 0xff;
          output[15] = (src_addr >> 24) & 0xff;
        
          output[16] = 224;
          output[17] = output[18] = 0;
          output[19] = 9;
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;
          output[24] = ((rip_len + 8) >> 8);
          output[25] = (rip_len + 8) & 0xff;
          output[26] = output[27] = 0;
          validateIPChecksum(output, rip_len + 20 + 8);
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          if (output[8] != 0)
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for ");
        printIP(src_addr);
      }
    }
  }
  return 0;
}
