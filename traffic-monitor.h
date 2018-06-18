#ifndef TRAFFIC_MONITOR_H
#define TRAFFIC_MONITOR_H

#include "mem-list.h"
#include "traffic-types.h"


void tm_add_entry(pool_t *monitor, struct monitor_entry *entry);
void tm_del_entry(pool_t *monitor, struct monitor_entry *entry);
void tm_print_traffic(pool_t *monitor);
void tm_update_traffic(pool_t *monitor);
void tm_update_arp_list(pool_t *arp);
int tm_update_monitor_list(pool_t *monitor, pool_t *arp);
void tm_update_iptables(pool_t *monitor);

#endif
