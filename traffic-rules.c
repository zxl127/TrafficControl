#include <traffic-rules.h>
#include <errno.h>


int tm_add_ipt_entry(const xt_chainlabel *chain, const struct ipt_entry *e, struct xtc_handle *handle)
{
    if(!handle || !e || !chain)
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

int tm_del_ipt_entry(const xt_chainlabel *chain, const struct ipt_entry *e, struct xtc_handle *handle)
{
    if (!e || !chain, !handle)
        return false;

    if(!iptc_delete_entry(chain, e, "", handle)) {
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
    struct ipt_entry *fw = NULL;
    struct ipt_entry_target *target = NULL;

    entry_size = XT_ALIGN(sizeof(struct ipt_entry));
    target_size = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(int));

    fw = calloc(1, entry_size + target_size);
    if ( !fw ) {
        printf("Malloc failure");
        return NULL;
    }

    fw->target_offset = entry_size;
    fw->next_offset = entry_size + target_size;
    fw->ip.proto = 0;
    fw->nfcache = NFC_UNKNOWN;

    if((fw->ip.src.s_addr = src.sin_addr.s_addr) == INADDR_ANY) {
        fw->ip.smsk.s_addr = 0;
    } else {
        fw->ip.smsk.s_addr = inet_addr("255.255.255.255");
    }

    if((fw->ip.dst.s_addr = dst.sin_addr.s_addr) == INADDR_ANY) {
        fw->ip.dmsk.s_addr = 0;
    } else {
        fw->ip.dmsk.s_addr = inet_addr("255.255.255.255");
    }

    target = (struct ipt_entry_target *)(fw->elems);
    target->u.target_size = target_size;
    if(label)
        strcpy(target->u.user.name, label);

    return fw;
}

struct ipt_entry *tm_get_jump_entry(const xt_chainlabel *chain)
{
    __u16 entry_size, target_size;
    struct ipt_entry *fw;
    struct ipt_entry_target *target;

    if(!chain)
        return NULL;

    entry_size = XT_ALIGN(sizeof(struct ipt_entry));
    target_size = XT_ALIGN(sizeof(struct ipt_entry_target) + sizeof(int));

    fw = calloc(1, entry_size + target_size);
    if(!fw)
        return NULL;
    fw->target_offset = entry_size;
    fw->next_offset = entry_size + target_size;
    fw->nfcache = NFC_UNKNOWN;

    target = (struct ipt_entry_target *)(fw->elems);
    target->u.target_size = target_size;
    strcpy(target->u.user.name, chain);

    return fw;
}

int tm_init_all_chain(struct iptc_handle *handle)
{
    struct ipt_entry *fw;

    if(!iptc_is_chain(TRAFFIC_IN_CHAIN, handle)) {
        if(!iptc_create_chain(TRAFFIC_IN_CHAIN, handle))
            goto end;
    }

    if(!iptc_is_chain(TRAFFIC_OUT_CHAIN, handle)) {
        if(!iptc_create_chain(TRAFFIC_OUT_CHAIN, handle))
            goto end;
    }

    fw = tm_get_jump_entry(TRAFFIC_IN_CHAIN);
    if(fw) {
        if(!iptc_check_entry("OUTPUT", fw, "", handle)) {
            if(!iptc_insert_entry("OUTPUT", fw, 0, handle))
                goto end;
        }
        free(fw);
    }

    fw = tm_get_jump_entry(TRAFFIC_OUT_CHAIN);
    if(fw) {
        if(!iptc_check_entry("INPUT", fw, "", handle)) {
            if(!iptc_insert_entry("INPUT", fw, 0, handle))
                goto end;
        }
        free(fw);
    }
    iptc_flush_entries(TRAFFIC_IN_CHAIN, handle);
    iptc_flush_entries(TRAFFIC_OUT_CHAIN, handle);

    return true;

end:
    free(fw);
    printf("%s\n", iptc_strerror(errno));
    return false;
}


