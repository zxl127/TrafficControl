#ifndef TRAFFIC_TYPES_H
#define TRAFFIC_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>


#define MAX_MAC_NUM     32


struct monitor_entry
{
    int enabledCtrl;
    unsigned char mac[8];
    struct in_addr ip;
    __u64 upload_bytes;
    __u64 download_bytes;
    __u64 upload_packets;
    __u64 download_packets;
    __u32 uplink;
    __u32 downlink;

    __u64 max_bytes;
    __u32 date_start;
    __u32 date_stop;
    __u32 daytime_start;
    __u32 daytime_stop;
};


struct traffic_setting {
    int method;
    unsigned char mac[MAX_MAC_NUM][8];
    unsigned int refresh_time;
    __u64 max_bytes;
    __u32 date_start;
    __u32 date_stop;
    __u32 daytime_start;
    __u32 daytime_stop;
    char output_file[128];
};



struct arp_info_entry
{
    struct in_addr ip;
    unsigned char mac[8];
    char dev[32];
};

struct ipt_info_entry
{
    struct in_addr sIp;
    struct in_addr dIp;
    __u64 bytes;
};



#endif
