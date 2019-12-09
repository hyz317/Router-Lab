#include "router.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <list>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

std::list<RoutingTableEntry> routeTable;
void printIP(uint32_t ip);

uint32_t swapInt32(uint32_t value) {
  return ((value & 0x000000ff) << 24) |
         ((value & 0x0000ff00) << 8) |
         ((value & 0x00ff0000) >> 8) |
         ((value & 0xff000000) >> 24);
}

void printRouteTable() {
  printf("len \t if_index \t nexthop \t metric \t timestamp \n");
  for (auto i = routeTable.begin(); i != routeTable.end(); i++) {
    printIP(i->addr);
    printIP(i->nexthop);
    printf("\t%u\t%u\t%u\t%ul\n", i->len, i->if_index, swapInt32(i->metric), i->timestamp);
  }
}

void encapRip(RipPacket* resp) {
  resp->numEntries = routeTable.size();
  resp->command = 2;
  int i = 0;
  for (auto routeEntry : routeTable) {
    RipEntry entry = {
      .addr = routeEntry.addr,
      .mask = ((unsigned)1 << routeEntry.len) - 1,
      .nexthop = routeEntry.nexthop,
      .metric = routeEntry.metric
    };
    resp->entries[i] = entry;
    i++;
  }
}

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  for (auto i = routeTable.begin(); i != routeTable.end(); i++) {
    if (i->addr == entry.addr && i->len == entry.len) {
      routeTable.erase(i);
      break;
    }
  }
  if (insert) {
    routeTable.push_back(entry);
  } else {

  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t metric = swapInt32(16)) {
  // TODO:
  for (int j = 32; j >= 0; j--) {
    for (auto i : routeTable) {
      // printf("%u %u %u %u\n", i.addr, i.len, i.if_index, i.nexthop);
      // printf("%u %u\n", swapInt32(i.addr), swapInt32(i.nexthop));
      unsigned long mask = (((unsigned long)1 << 32) - 1) - (((unsigned long)1 << (32 - j)) - 1);
      // if (j == 32) {
      //   printf("%08lx %08lx %d %d\n", swapInt32(i.addr) & mask, swapInt32(addr) & mask, (i.len == j), (swapInt32(i.addr) & mask) == (swapInt32(addr) & mask));
      // }
      if ((i.len == j) && ((swapInt32(i.addr) & mask)) == (swapInt32(addr) & mask)) {
        *nexthop = i.nexthop;
        *if_index = i.if_index;
        printf("metric: %08x i.metric: %08x\n", swapInt32(metric), swapInt32(i.metric));
        if (swapInt32(i.metric) > swapInt32(metric) + 1) {
          i.metric = swapInt32(swapInt32(metric) + 1);
        }
        return true;
      }
    }
  }
  *nexthop = 0;
  *if_index = 0;
  return false;
}
