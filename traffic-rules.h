#ifndef TRAFFIC_RULES_H
#define TRAFFIC_RULES_H

#include "xtables.h"
#include "iptables.h"
#include <linux/netfilter/nf_nat.h>

#define TRAFFIC_OUT_CHAIN   "TRAFFIC_OUT"
#define TRAFFIC_IN_CHAIN    "TRAFFIC_IN"

void tm_set_entry(struct sockaddr_in src, struct sockaddr_in dst, const char *label, struct ipt_entry *rule);
void tm_set_jump_entry(const xt_chainlabel chain, struct ipt_entry *rule);
int tm_init_all_chain(struct iptc_handle *handle);

#endif
