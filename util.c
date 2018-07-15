#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include "util.h"



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

    setenv("TZ", "UTC", true);
    tzset();
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

int time_check(time_t start, time_t stop)
{
    if(start < stop)
        return true;
    else
        return false;
}

void time_divide(unsigned int fulltime, unsigned int *hours,
    unsigned int *minutes, unsigned int *seconds)
{
    *seconds  = fulltime % 60;
    fulltime /= 60;
    *minutes  = fulltime % 60;
    *hours    = fulltime / 60;
}

void time_print_daytime(time_t time, char *daytime)
{
    unsigned int h, m, s;

    time_divide(time, &h, &m, &s);
    sprintf(daytime, "%02u:%02u:%02u", h, m, s);
}

void time_print_date(time_t date, char *utc)
{
    struct tm *t;

    if (date == 0) {
        strcpy(utc, "0000-00-00T00:00:00");
        return;
    }

    t = gmtime(&date);
    sprintf(utc, "%04u-%02u-%02uT%02u:%02u:%02u",
           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
           t->tm_hour, t->tm_min, t->tm_sec);
}


long long parse_traffic_data(const char *s)
{
    char *e;
    double f;

    f = strtod(s, &e);
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

    return (long long)f;
}

void print_readable_traffic(unsigned long bytes, char *readable)
{
    unsigned int i = 0;
    float n = (float)bytes;

    while(n >= 1024) {
        n = n / 1024;
        i++;
    };

    switch (i) {
    case 0:
        sprintf(readable, "%luB", bytes);
        break;
    case 1:
        sprintf(readable, "%.2fK", n);
        break;
    case 2:
        sprintf(readable, "%.2fM", n);
        break;
    case 3:
        sprintf(readable, "%.2fG", n);
        break;
    default:
        sprintf(readable, "%luB", bytes);
        break;
    }
}


