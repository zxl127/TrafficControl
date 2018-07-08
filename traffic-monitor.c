#include "util.h"
#include "traffic-rules.h"
#include "traffic-monitor.h"

extern struct traffic_setting global;

void tm_add_entry(pool_t *monitor, struct monitor_entry *entry)
{
    mem_t *m;
    struct monitor_entry *m_entry;

    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        if(memcmp(m_entry->mac, entry->mac, ETH_ALEN) == 0) {
            m_entry->enabledCtrl = true;
            m_entry->max_bytes = entry->max_bytes;
            m_entry->date_start = entry->date_start;
            m_entry->date_stop = entry->date_stop;
            m_entry->daytime_start = entry->daytime_start;
            m_entry->daytime_stop = entry->daytime_stop;
            return;
        }
    }
    entry->enabledCtrl = true;
    monitor->add_mem(monitor, entry, sizeof(struct monitor_entry));
}

void tm_del_entry(pool_t *monitor, struct monitor_entry *entry)
{
    mem_t *mm;
    struct monitor_entry *m_entry;

    list_for_each_entry(mm, &monitor->used_list, list) {
        m_entry = mm->mem;
        if(memcmp(m_entry->mac, entry->mac, ETH_ALEN) == 0)
            m_entry->enabledCtrl = false;
    }
}

void tm_update_arp_list(pool_t *arp)
{
    FILE *fp;
    char line[128];
    char ip[128];
    char hwa[128];
    char mask[128];
    char dev[128];
    int type, flags;
    int num;
    struct arp_info_entry entry;

    arp->del_all(arp);
    fp = fopen("/proc/net/arp", "r");
    if(!fp) {
        perror("Open arp file error");
        return;
    }

    fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        mask[0] = '-'; mask[1] = '\0';
        dev[0] = '-'; dev[1] = '\0';

        num = sscanf(line, "%s 0x%x 0x%x %s %s %s\n",
                     ip, &type, &flags, hwa, mask, dev);
        if (num < 4) {
            break;
        }

        entry.ip.s_addr = inet_addr(ip);
        memcpy(entry.mac, str2mac(hwa), ETH_ALEN);
        snprintf(entry.dev, 32, "%s", dev);
        arp->add_mem(arp, &entry, sizeof(entry));
    }
    fclose(fp);
}

int tm_update_ipt_list(pool_t *ipt, const char *chain)
{
    FILE *fp;
    int num;
    char cmd[128];
    char line[128];
    struct ipt_info_entry entry;
    char pkts[32], bytes[32];
    char buf1[32], buf2[32], buf3[32];

    sprintf(cmd, "echo \"7890\" | sudo -S iptables -vxnL %s", chain);
    fp = popen(cmd, "r");
    if(!fp) {
        return false;
    }

    fgets(line, sizeof(line), fp);
    fgets(line, sizeof(line), fp);
    while(fgets(line, sizeof(line), fp)) {
        num = sscanf(line, "%s %s %*s %*s %*s %*s %s %s %s",
                     pkts, bytes, buf1, buf2, buf3);
        if(num < 4) {
            break;
        }
        if(num == 4) {
            entry.sIp.s_addr = inet_addr(buf1);
            entry.dIp.s_addr = inet_addr(buf2);
        } else {
            entry.sIp.s_addr = inet_addr(buf2);
            entry.dIp.s_addr = inet_addr(buf3);
        }
        entry.bytes = atoi(bytes);
        ipt->add_mem(ipt, &entry, sizeof(entry));
    }
    fclose(fp);

    return true;
}


int tm_update_monitor_list(pool_t *monitor, pool_t *arp)
{
    int changed = false;
    int find = false;
    mem_t *mm, *ma, *tmp;
    struct monitor_entry *monitor_entry, m_entry;
    struct arp_info_entry *arp_entry;

    list_for_each_entry_safe(mm, tmp, &monitor->used_list, list) {
        find = false;
        monitor_entry = mm->mem;
        list_for_each_entry(ma, &arp->used_list, list) {
            arp_entry = ma->mem;
            if(memcmp(arp_entry->mac, monitor_entry->mac, ETH_ALEN) == 0) {
                if(monitor_entry->ip.s_addr != arp_entry->ip.s_addr) {
                    monitor_entry->ip = arp_entry->ip;
                    changed = true;
                }
                arp->del_mem(arp, ma);
                find = true;
                break;
            }
        }
        if(!find && !monitor_entry->enabledCtrl) {
            monitor->del_mem(monitor, mm);
            changed = true;
        }
    }

    list_for_each_entry(ma, &arp->used_list, list) {
        arp_entry = ma->mem;
        memset(&m_entry, 0, sizeof(m_entry));
        memcpy(m_entry.mac, arp_entry->mac, ETH_ALEN);
        m_entry.ip = arp_entry->ip;
        monitor->add_mem(monitor, &m_entry, sizeof(m_entry));
        changed = true;
    }

    return changed;
}

void tm_print_traffic(pool_t *monitor)
{
    mem_t *m;
    char buf[64];
    struct monitor_entry *m_entry;

    term_reset_cursor();
    term_clear_screen();
    printf("%-2s %-17s %-15s %-8s %-8s %-10s %-10s %-8s %-19s %-19s %-9s %-9s\n",
           "on", "mac", "ip", "uBytes", "dBytes", "uplink", "downlink", "maxBytes", "DateStart",
           "DateStop", "TimeStart", "TimeStop");
    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        printf("%-2d ", m_entry->enabledCtrl);
        printf("%-17s ", mac2str(m_entry->mac));
        printf("%-15s ", inet_ntoa(m_entry->ip));
        print_readable_traffic(m_entry->upload_bytes, buf);
        printf("%-8s ", buf);
        print_readable_traffic(m_entry->download_bytes, buf);
        printf("%-8s ", buf);
        print_readable_traffic(m_entry->uplink, buf);
        strcat(buf, "/s");
        printf("%-10s ", buf);
        print_readable_traffic(m_entry->downlink, buf);
        strcat(buf, "/s");
        printf("%-10s ", buf);
        print_readable_traffic(m_entry->max_bytes, buf);
        printf("%-8s ", buf);
        time_print_date(m_entry->date_start, buf);
        printf("%-19s ", buf);
        time_print_date(m_entry->date_stop, buf);
        printf("%-19s ", buf);
        time_print_daytime(m_entry->daytime_start, buf);
        printf("%-9s ", buf);
        time_print_daytime(m_entry->daytime_stop, buf);
        printf("%-9s\n", buf);
    }
}

void tm_update_traffic(pool_t *monitor)
{
    mem_t *m;
//    unsigned int rulenum;
    struct iptc_handle *handle;
    struct monitor_entry *m_entry;
    const struct ipt_entry *rule;
//    struct xt_counters *xtc;

    handle = iptc_init("filter");
    if(!handle)
        return;
#if 0
    rulenum = 1;
    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        xtc = iptc_read_counter(TRAFFIC_IN_CHAIN, rulenum, handle);
        if(xtc) {
            m_entry->download_bytes = xtc->bcnt;
            m_entry->download_packets = xtc->pcnt;
        }
        xtc = iptc_read_counter(TRAFFIC_OUT_CHAIN, rulenum, handle);
        if(xtc) {
            m_entry->upload_bytes = xtc->bcnt;
            m_entry->upload_packets = xtc->pcnt;
        }
        rulenum++;
    }
#else
    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        for(rule = iptc_first_rule(TRAFFIC_IN_CHAIN, handle); rule; rule = iptc_next_rule(rule, handle)) {
            if(m_entry->ip.s_addr == rule->ip.dst.s_addr && rule->ip.src.s_addr == INADDR_ANY) {
                m_entry->downlink = (__u32)((rule->counters.bcnt - m_entry->download_bytes) * 1.0 / (global.refresh_time * 1.0 / 1000));
                m_entry->download_bytes = rule->counters.bcnt;
                m_entry->download_packets = rule->counters.pcnt;
                break;
            }
        }

        for(rule = iptc_first_rule(TRAFFIC_OUT_CHAIN, handle); rule; rule = iptc_next_rule(rule, handle)) {
            if(m_entry->ip.s_addr == rule->ip.src.s_addr && rule->ip.dst.s_addr == INADDR_ANY) {
                m_entry->uplink = (__u32)((rule->counters.bcnt - m_entry->upload_bytes) * 1.0 / (global.refresh_time * 1.0 / 1000));
                m_entry->upload_bytes = rule->counters.bcnt;
                m_entry->upload_packets = rule->counters.pcnt;
                break;
            }
        }
    }
#endif
    iptc_free(handle);
}

void tm_update_iptables(pool_t *monitor)
{
    char *label;
    struct iptc_handle *handle;
    static struct ipt_entry *rule = NULL;
//    struct xt_counters xtc;
    mem_t *m;
    struct monitor_entry *me;
    struct sockaddr_in sin1, sin2;

    handle = iptc_init("filter");
    if(!handle) {
        printf("%s\n", iptc_strerror(errno));
        return;
    }
    if(tm_init_all_chain(handle) == false)
        goto end;

    if(!rule) {
        rule = calloc(1, XT_ALIGN(sizeof(struct ipt_entry)) + XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(int)));
        if(!rule)
            goto end;
    }

    sin1.sin_port = -1;
    sin2.sin_addr.s_addr = htonl(INADDR_ANY);
    sin2.sin_port = -1;
    list_for_each_entry(m, &monitor->used_list, list) {
        me = m->mem;
        sin1.sin_addr = me->ip;
        if(me->enabledCtrl && me->download_bytes + me->upload_bytes >= me->max_bytes) {
            label = IPTC_LABEL_DROP;
        } else {
            label = NULL;
        }

        tm_set_entry(sin1, sin2, label, rule);
        rule->counters.bcnt = me->upload_bytes;
        rule->counters.pcnt = me->upload_packets;
        iptc_append_entry(TRAFFIC_OUT_CHAIN, rule, handle);
//        printf("upload: %d, %d\n", xtc.bcnt, xtc.pcnt);

        tm_set_entry(sin2, sin1, label, rule);
        rule->counters.bcnt = me->download_bytes;
        rule->counters.pcnt = me->download_packets;
        iptc_append_entry(TRAFFIC_IN_CHAIN, rule, handle);
//        printf("download: %d, %d\n", xtc.bcnt, xtc.pcnt);
    }
    iptc_commit(handle);

end:
    iptc_free(handle);
}

