#ifndef UTIL_H
#define UTIL_H

#include <time.h>
#include <stdbool.h>

#define ETH_ALEN 6

#define term_show_cursor()      printf("\033[?25h")
#define term_reset_cursor()     printf("\033[H")
#define term_hide_cursor()      printf("\033[?25l")
#define term_clear_screen()     printf("\033[2J")



int isValidIp(char *value);
int isValidMac(char *value);
int zero_mac(unsigned char mac[]);
const char *mac2str(unsigned char mac[]);
const unsigned char *str2mac(char *str);
void macs2str(unsigned char macs[][8], char *str, int macs_len);
int str2macs(char *str, unsigned char macs[][8], int macs_len);
time_t time_parse_date(const char *s, bool end);
int time_parse_minutes(const char *s);
int time_check(time_t start, time_t stop);
void time_divide(unsigned int fulltime, unsigned int *hours, unsigned int *minutes, unsigned int *seconds);
void time_print_daytime(time_t time, char *daytime);
void time_print_date(time_t date, char *utc);
long parse_traffic_data(const char *s);
void print_readable_traffic(unsigned long bytes, char *readable);

#endif
