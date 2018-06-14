#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <mem-list.h>

#define ETH_ALEN 6

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
    int bytes;
};


const char *mac2str(unsigned char mac[]);
const unsigned char *str2mac(char *str);
int init_arp_cache_list(pool_t *arp);
