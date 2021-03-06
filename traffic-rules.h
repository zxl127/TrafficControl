#ifndef TRAFFIC_RULES_H
#define TRAFFIC_RULES_H

#include "xtables.h"
#include "iptables.h"
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/xt_time.h>

#define TRAFFIC_OUT_CHAIN   "TRAFFIC_OUT"
#define TRAFFIC_IN_CHAIN    "TRAFFIC_IN"

struct ipt_entry *tm_get_entry(struct sockaddr_in src, struct sockaddr_in dst, const char *label);
struct ipt_entry *tm_get_time_limit_entry(struct sockaddr_in src, struct sockaddr_in dst, struct xt_time_info time, const char *label);
struct ipt_entry *tm_get_jump_entry(const xt_chainlabel chain);
int tm_init_all_chain(struct iptc_handle *handle);

#endif
