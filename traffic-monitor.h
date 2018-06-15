#include <linux/types.h>
#include <util.h>

struct monitor_entry
{
    unsigned char mac[8];
    struct in_addr ip;
    __u64 upload_bytes;
    __u64 download_bytes;
    __u64 upload_packets;
    __u64 download_packets;
    __u64 uplink;
    __u64 downlink;

    int enabledCtrl;
    __u64 max_bytes;
    __u32 date_start;
    __u32 date_stop;
    __u32 daytime_start;
    __u32 daytime_stop;
};

void tm_add_entry(pool_t *monitor, struct monitor_entry *entry);
void tm_upate_list(pool_t *monitor, pool_t *arp);
void tm_update_traffic(pool_t *monitor);
void tm_print_traffic(pool_t *monitor);
void tm_update_iptables(pool_t *monitor);
int test_counter(void);
