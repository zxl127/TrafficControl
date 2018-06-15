#include <errno.h>
#include <traffic-rules.h>
#include <traffic-monitor.h>


void tm_add_entry(pool_t *monitor, struct monitor_entry *entry)
{
    mem_t *m;
    struct monitor_entry *m_entry;

    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        if(memcmp(m_entry->mac, entry->mac, ETH_ALEN) == 0) {
            m_entry->enabledCtrl = entry->enabledCtrl;
            m_entry->max_bytes = entry->max_bytes;
            m_entry->date_start = entry->date_start;
            m_entry->date_stop = entry->date_stop;
            m_entry->daytime_start = entry->daytime_start;
            m_entry->daytime_stop = entry->daytime_stop;
            return;
        }
    }
    monitor->add_mem(monitor, entry, sizeof(struct monitor_entry));
}

void tm_upate_list(pool_t *monitor, pool_t *arp)
{
    int find = false;
    mem_t *mm, *ma;
    struct monitor_entry *monitor_entry, m_entry;
    struct arp_info_entry *arp_entry;

    list_for_each_entry(mm, &monitor->used_list, list) {
        find = false;
        monitor_entry = mm->mem;
        list_for_each_entry(ma, &arp->used_list, list) {
            arp_entry = ma->mem;
            if(memcmp(arp_entry->mac, monitor_entry->mac, ETH_ALEN) == 0) {
                monitor_entry->ip = arp_entry->ip;
                arp->del_mem(arp, ma);
                find = true;
                break;
            }
        }
        if(!find && !monitor_entry->enabledCtrl) {
            monitor->del_mem(monitor, mm);
        }
    }

    list_for_each_entry(ma, &arp->used_list, list) {
        arp_entry = ma->mem;
        memset(&m_entry, 0, sizeof(m_entry));
        memcpy(m_entry.mac, arp_entry->mac, ETH_ALEN);
        m_entry.ip = arp_entry->ip;
        monitor->add_mem(monitor, &m_entry, sizeof(m_entry));
    }
}

void tm_print_traffic(pool_t *monitor)
{
    mem_t *m;
    struct monitor_entry *m_entry;

    // Reset cursor
    printf("\033[H");
    // Hide cursor
    printf("\033[?25l");
    // Clear screen
    printf("\033[2J");
    printf("%-17s\t%-15s\t%-16s\t%-16s\n", "mac", "ip", "upload bytes", "download bytes");
    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        printf("%-17s\t", mac2str(m_entry->mac));
        printf("%-15s\t", inet_ntoa(m_entry->ip));
        printf("%-16d\t", m_entry->upload_bytes);
        printf("%-16d\n", m_entry->download_bytes);
    }
}

void tm_update_traffic(pool_t *monitor)
{
    mem_t *m;
    unsigned int rulenum;
    struct iptc_handle *handle;
    struct monitor_entry *m_entry;
    struct ipt_entry *rule;
    struct xt_counters *xtc;

    handle = iptc_init("filter");
    if(!handle)
        return;
#if 1
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
#endif
#if 0
    rule = iptc_first_rule(TRAFFIC_IN_CHAIN, handle);
    if(!rule)
        goto end;
    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        m_entry->download_bytes = rule->counters.bcnt;
        m_entry->download_packets = rule->counters.pcnt;
        rule = iptc_next_rule(rule, handle);
        if(!rule)
            break;
    }

    rule = iptc_first_rule(TRAFFIC_OUT_CHAIN, handle);
    if(!rule)
        goto end;
    list_for_each_entry(m, &monitor->used_list, list) {
        m_entry = m->mem;
        m_entry->upload_bytes = rule->counters.bcnt;
        m_entry->upload_packets = rule->counters.pcnt;
        rule = iptc_next_rule(rule, handle);
        if(!rule)
            break;
    }
#endif
end:
    iptc_free(handle);
}

void tm_update_iptables(pool_t *monitor)
{
    char *label;
    int rulenum;
    int ok;
    struct iptc_handle *handle;
    struct ipt_entry *fw;
    struct xt_counters xtc;
    mem_t *m;
    struct monitor_entry *me;
    struct sockaddr_in sin1, sin2;

    handle = iptc_init("filter");
    if(!handle) {
        printf("%s\n", iptc_strerror(errno));
        return;
    }
    ok = tm_init_all_chain(handle);
    if(!ok)
        goto end;

    sin1.sin_port = -1;
    sin2.sin_addr.s_addr = htonl(INADDR_ANY);
    sin2.sin_port = -1;
    rulenum = 1;
    list_for_each_entry(m, &monitor->used_list, list) {
        me = m->mem;
        sin1.sin_addr = me->ip;
        if(me->enabledCtrl && me->download_bytes + me->upload_bytes >= me->max_bytes) {
            label = IPTC_LABEL_DROP;
        } else {
            label = NULL;
        }

        fw = tm_get_entry(sin1, sin2, label);
        if(fw) {
            iptc_append_entry(TRAFFIC_OUT_CHAIN, fw, handle);
            xtc.pcnt = me->upload_packets;
            xtc.bcnt = me->upload_bytes;
//            printf("upload: %d, %d\n", xtc.bcnt, xtc.pcnt);
            iptc_set_counter(TRAFFIC_OUT_CHAIN, rulenum, &xtc, handle);
            free(fw);
        }
        fw = tm_get_entry(sin2, sin1, label);
        if(fw) {
            iptc_append_entry(TRAFFIC_IN_CHAIN, fw, handle);
            xtc.pcnt = me->download_packets;
            xtc.bcnt = me->download_bytes;
//            printf("download: %d, %d\n", xtc.bcnt, xtc.pcnt);
            iptc_set_counter(TRAFFIC_IN_CHAIN, rulenum, &xtc, handle);
            free(fw);
        }
        rulenum++;
    }
    iptc_commit(handle);

end:
    iptc_free(handle);
}

int test_counter(void)
{
    char *label;
    int rulenum;
    int ok;
    struct iptc_handle *handle;
    struct ipt_entry *fw;
    struct xt_counters xtc;
    mem_t *m;
    struct monitor_entry *me;
    struct sockaddr_in sin1, sin2;


    handle = iptc_init("filter");
    if(!handle) {
        printf("%s\n", iptc_strerror(errno));
        return;
    }
    ok = tm_init_all_chain(handle);
    if(!ok) {
        iptc_free(handle);
        return;
    }


    sin1.sin_addr.s_addr = inet_addr("192.168.0.123");
    sin1.sin_port = -1;
    sin2.sin_addr.s_addr = htonl(INADDR_ANY);
    sin2.sin_port = -1;


    fw = tm_get_entry(sin1, sin2, label);
    if(fw) {
        iptc_append_entry(TRAFFIC_IN_CHAIN, fw, handle);
        free(fw);
    }

    xtc.pcnt = 111;
    xtc.bcnt = 22222;
    printf("download: %d, %d\n", xtc.bcnt, xtc.pcnt);
    iptc_set_counter(TRAFFIC_IN_CHAIN, 1, &xtc, handle);

    iptc_commit(handle);
    iptc_free(handle);
}


