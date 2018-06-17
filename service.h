#ifndef SERVER_H
#define SERVER_H

#include "traffic-monitor.h"


#define CMD_METHOD_A    1
#define CMD_METHOD_D    2
#define CMD_METHOD_F    3


struct traffic_setting {
    int method;
    unsigned char mac[MAX_MAC_NUM][8];
    int refresh_time;
    __u64 max_bytes;
    __u32 date_start;
    __u32 date_stop;
    __u32 daytime_start;
    __u32 daytime_stop;
};


int response_client_request(FILE *f, int success, const char *msg);
int parse_server_response(FILE *f);
int send_client_request(FILE *f, struct traffic_setting *setting);
int parse_client_request(FILE *f, struct traffic_setting *setting);
void apply_client_settings(struct traffic_setting *setting, pool_t *monitor);
int init_server(void);
void free_server(void);
void init_client(struct traffic_setting *setting);

#endif // SERVER_H
