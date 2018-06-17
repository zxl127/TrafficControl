#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "mem-list.h"

#define ETH_ALEN 6

#define MAX_MAC_NUM     32

#define term_show_cursor()      printf("\033[?25h")
#define term_reset_cursor()     printf("\033[H")
#define term_hide_cursor()      printf("\033[?25l")
#define term_clear_screen()     printf("\033[2J")

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



int isValidIp(char *value);
int isValidMac(char *value);
int zero_mac(unsigned char mac[]);
const char *mac2str(unsigned char mac[]);
const unsigned char *str2mac(char *str);
void macs2str(unsigned char macs[][8], char *str, int macs_len);
int str2macs(char *str, unsigned char macs[][8], int macs_len);
int parse_arp_cache_list(pool_t *arp);
time_t time_parse_date(const char *s, bool end);
int time_parse_minutes(const char *s);
long parse_traffic_data(const char *s);
