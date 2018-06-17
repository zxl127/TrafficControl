#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <time.h>
#include "util.h"
#include "json.h"



//0: valid
int evalReg(char *pattern, char *value)
{
    int r, cflags = 0;
    regmatch_t pm[10];
    const size_t nmatch = 10;
    regex_t reg;

    r = regcomp(&reg, pattern, cflags);
    if(r == 0){
        r = regexec(&reg, value, nmatch, pm, cflags);
    }
    regfree(&reg);

    return r;
}

int isValidIp(char *value)
{
    int r;
    char *reg = "^[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}$";
    r = evalReg(reg, value);
    return r;
}

int isValidMac(char *value)
{
    int r;
    char *reg = "^([A-Fa-f0-9]{2}[-,:]){5}[A-Fa-f0-9]{2}$";
    r = evalReg(reg, value);
    return r;
}

static unsigned char a2x(const char c)
{
    switch(c) {
    case '0'...'9':
        return 0x0 + (c-'0');
    case 'a'...'f':
        return 0xa + (c-'a');
    case 'A'...'F':
        return 0xa + (c-'A');
    default:
        return 0;
    }
}

const char *mac2str(unsigned char mac[ETH_ALEN])
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

void macs2str(unsigned char macs[][8], char *str, int macs_len)
{
    int i;

    *str = '\0';
    for(i = 0; i < macs_len; ++i) {
        if(zero_mac(macs[i]))
            break;
        strcat(str, mac2str(macs[i]));
        strcat(str, ",");
    }
    str[strlen(str) - 1] = '\0';
}

int str2macs(char *str, unsigned char macs[][8], int macs_len)
{
    int i = 0;
    char *p;

    p = strtok(str, ",");
    while(p && i < macs_len) {
        if(!isValidMac(p))
            return false;
        memcpy(macs[i], str2mac(p), ETH_ALEN);
        p = strtok(NULL, ",");
        i++;
    }
    return true;
}


int zero_mac(unsigned char mac[])
{
    return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
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

int parse_arp_cache_list(pool_t *arp)
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

time_t time_parse_date(const char *s, bool end)
{
    unsigned int month = 1, day = 1, hour = 0, minute = 0, second = 0;
    unsigned int year  = end ? 2038 : 1970;
    const char *os = s;
    struct tm tm;
    time_t ret;
    char *e;

    year = strtoul(s, &e, 10);
    if ((*e != '-' && *e != '\0') || year < 1970 || year > 2038)
        goto out;
    if (*e == '\0')
        goto eval;

    s = e + 1;
    month = strtoul(s, &e, 10);
    if ((*e != '-' && *e != '\0') || month > 12)
        goto out;
    if (*e == '\0')
        goto eval;

    s = e + 1;
    day = strtoul(s, &e, 10);
    if ((*e != 'T' && *e != '\0') || day > 31)
        goto out;
    if (*e == '\0')
        goto eval;

    s = e + 1;
    hour = strtoul(s, &e, 10);
    if ((*e != ':' && *e != '\0') || hour > 23)
        goto out;
    if (*e == '\0')
        goto eval;

    s = e + 1;
    minute = strtoul(s, &e, 10);
    if ((*e != ':' && *e != '\0') || minute > 59)
        goto out;
    if (*e == '\0')
        goto eval;

    s = e + 1;
    second = strtoul(s, &e, 10);
    if (*e != '\0' || second > 59)
        goto out;

 eval:
    tm.tm_year = year - 1900;
    tm.tm_mon  = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min  = minute;
    tm.tm_sec  = second;
    tm.tm_isdst = 0;

//	setenv("TZ", "UTC", true);
//	tzset();
    ret = mktime(&tm);
    if (ret >= 0)
        return ret;
    perror("mktime returned an error");

 out:
    printf("Invalid date \"%s\" specified. Should "
           "be YYYY[-MM[-DD[Thh[:mm[:ss]]]]]\n", os);

    return -1;
}

int time_parse_minutes(const char *s)
{
    unsigned int hour, minute, second = 0;
    char *e;

    hour = strtoul(s, &e, 10);
    if (*e != ':' || hour > 23)
        goto out;

    s = e + 1;
    minute = strtoul(s, &e, 10);
    if ((*e != ':' && *e != '\0') || minute > 59)
        goto out;
    if (*e == '\0')
        goto eval;

    s = e + 1;
    second = strtoul(s, &e, 10);
    if (*e != '\0' || second > 59)
        goto out;

 eval:
    return 60 * 60 * hour + 60 * minute + second;

 out:
    printf("Invalid time \"%s\" specified, "
               "should be hh:mm[:ss] format and within the boundaries\n", s);
    return -1;
}

long parse_traffic_data(const char *s)
{
    char *e;
    float f;

    f = strtof(s, &e);
    switch (*e) {
    case 'G':
        f = f * 1024 * 1024 * 1024;
        break;
    case 'M':
        f = f * 1024 * 1024;
        break;
    case 'K':
        f = f * 1024;
        break;
    case 'B':
    case '\0':
        break;
    default:
        printf("Invalid traffic \"%s\" specified, should be G/M/K/B format\n", s);
        return -1;
    }

    return (long)f;
}


