#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <util.h>



static unsigned char a2x(const char c)
{
    switch(c) {
    case '0'...'9':
        return (unsigned char)atoi(&c);
    case 'a'...'f':
        return 0xa + (c-'a');
    case 'A'...'F':
        return 0xa + (c-'A');
    default:
        return 0;
    }
}

const char *mac2str(unsigned char mac[])
{
    static char str[32];
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return str;
}

const unsigned char *str2mac(char *str)
{
    int i;
    static unsigned char mac[6];

    for(i = 0; i < ETH_ALEN; i++) {
        mac[i] = (a2x(str[i*3]) << 4) + a2x(str[i*3 + 1]);
    }
    return mac;
}


int getFileTotalLine(FILE *fp)
{
    int num = 0;
    int pos;

    if(fp == NULL)
      return -1;

    pos = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    while(!feof(fp))
    {
        if(fgetc(fp) == '\n')
            ++num;
    }
    fseek(fp, pos, SEEK_SET);

    return num;
}

const char *getTrafficIptEntry(const char *chain, const char *ip, bool sIp)
{
    static char entry[256];

    if(sIp)
        sprintf(entry, "iptables -A %s -s %s", chain, ip);
    else
        sprintf(entry, "iptables -A %s -d %s", chain, ip);

    return entry;
}

int init_arp_cache_list(pool_t *arp)
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
        return false;
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

    return true;
}

int init_ipt_list(pool_t *ipt, const char *chain)
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
