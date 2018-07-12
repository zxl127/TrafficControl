#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "traffic-rules.h"


int tm_add_ipt_entry(const xt_chainlabel chain, const struct ipt_entry *e, struct xtc_handle *handle)
{
    if(!handle || !e)
        return false;

    if(!iptc_append_entry(chain, e, handle)) {
        printf("%s\n", iptc_strerror(errno));
        return false;
    }
    if(!iptc_commit(handle)) {
        printf("%s\n", iptc_strerror(errno));
        return false;
    }

    return true;
}

int tm_del_ipt_entry(const xt_chainlabel chain, const struct ipt_entry *e, struct xtc_handle *handle)
{
    if (!e || !handle)
        return false;

    if(!iptc_delete_entry(chain, e, (unsigned char *)"", handle)) {
        printf("%s\n", iptc_strerror(errno));
        return false;
    }
    if(!iptc_commit(handle)) {
        printf("%s\n", iptc_strerror(errno));
        return false;
    }

    return true;
}

struct ipt_entry *tm_get_entry(struct sockaddr_in src, struct sockaddr_in dst, const char *label)
{
    __u16 entry_size, target_size;
    struct ipt_entry_target *target;
    static struct ipt_entry *rule = NULL;

    entry_size = XT_ALIGN(sizeof(struct ipt_entry));
    target_size = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(int));

    if(!rule) {
        rule = calloc(1, entry_size + target_size);
        if(!rule)
            return NULL;
    }

    rule->target_offset = entry_size;
    rule->next_offset = entry_size + target_size;
    rule->ip.proto = 0;
    rule->nfcache = NFC_UNKNOWN;

    if((rule->ip.src.s_addr = src.sin_addr.s_addr) == INADDR_ANY) {
        rule->ip.smsk.s_addr = 0;
    } else {
        rule->ip.smsk.s_addr = inet_addr("255.255.255.255");
    }

    if((rule->ip.dst.s_addr = dst.sin_addr.s_addr) == INADDR_ANY) {
        rule->ip.dmsk.s_addr = 0;
    } else {
        rule->ip.dmsk.s_addr = inet_addr("255.255.255.255");
    }

    target = (struct ipt_entry_target *)(rule->elems);
    target->u.target_size = target_size;
    if(label)
        strcpy(target->u.user.name, label);
    else
        strcpy(target->u.user.name, "");

    return rule;
}

struct ipt_entry *tm_get_jump_entry(const xt_chainlabel chain)
{
    __u16 entry_size, target_size;
    struct ipt_entry_target *target;
    static struct ipt_entry *rule = NULL;

    entry_size = XT_ALIGN(sizeof(struct ipt_entry));
    target_size = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(int));

    if(!rule) {
        rule = calloc(1, entry_size + target_size);
        if(!rule)
            return NULL;
    }

    rule->target_offset = entry_size;
    rule->next_offset = entry_size + target_size;
    rule->nfcache = NFC_UNKNOWN;

    target = (struct ipt_entry_target *)(rule->elems);
    target->u.target_size = target_size;
    strcpy(target->u.user.name, chain);

    return rule;
}

int tm_init_all_chain(struct iptc_handle *handle)
{
    struct ipt_entry *rule;

    if(!iptc_is_chain(TRAFFIC_IN_CHAIN, handle)) {
        if(!iptc_create_chain(TRAFFIC_IN_CHAIN, handle))
            goto end;
    }

    if(!iptc_is_chain(TRAFFIC_OUT_CHAIN, handle)) {
        if(!iptc_create_chain(TRAFFIC_OUT_CHAIN, handle))
            goto end;
    }

    rule = tm_get_jump_entry(TRAFFIC_IN_CHAIN);
    if(!iptc_check_entry("OUTPUT", rule, (unsigned char *)"", handle)) {
        if(!iptc_insert_entry("OUTPUT", rule, 0, handle))
            goto end;
    }

    rule = tm_get_jump_entry(TRAFFIC_OUT_CHAIN);
    if(!iptc_check_entry("INPUT", rule, (unsigned char *)"", handle)) {
        if(!iptc_insert_entry("INPUT", rule, 0, handle))
            goto end;
    }

    if(!iptc_flush_entries(TRAFFIC_IN_CHAIN, handle))
        goto end;
    if(!iptc_flush_entries(TRAFFIC_OUT_CHAIN, handle))
        goto end;

    return true;

end:
    printf("%s\n", iptc_strerror(errno));
    return false;
}


