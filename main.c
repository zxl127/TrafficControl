#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "usock.h"
#include "utask.h"
#include "util.h"
#include "service.h"
#include "output.h"
#include "traffic-monitor.h"

pool_t arp, monitor;
struct traffic_setting global;


struct option long_opts[] = {
    {"foregroud", no_argument, NULL, '1'},
    {"help", no_argument, NULL, '2'},
    {"max-bytes", required_argument, NULL, '3'},
    {"date-start", required_argument, NULL, '4'},
    {"date-stop", required_argument, NULL, '5'},
    {"daytime-start", required_argument, NULL, '6'},
    {"daytime-stop", required_argument, NULL, '7'},
    {NULL}
};

static void print_help(char *name)
{
    printf("Usage: %s [OPTIONS]\n", name);
    printf(" -f, --foreground        Run in the foreground\n");
    printf(" -i, --interval          Refresh traffic information interval\n");
    printf(" -h, --help              Display this help text\n");
    printf(" -v, --version           Display the %s version\n", name);
}

void traffic_refresh_timeout(utimer_t *t)
{
    tm_update_traffic(&monitor);
    tm_print_traffic(&monitor);
    tm_update_arp_list(&arp);
    tm_update_monitor_list(&monitor, &arp);
    tm_update_iptables(&monitor);
    tm_output_traffic_info(&monitor, global.output_file);

    utimer_set(t, global.refresh_time);
    utimer_add(t);
}

int main(int argc, char **argv)
{
    int c;
    bool foreground = false;
    bool isServer = false;
    utimer_t refresh_timer = {.handler = traffic_refresh_timeout};

    memset(&global, 0, sizeof(global));

    while(1) {
        c = getopt_long(argc, argv, "A:D:fFht:o:S", long_opts, NULL);
        if(c == EOF)
            break;
        switch (c) {
        case 'A':
            global.method = CMD_METHOD_A;
            str2macs(optarg, global.mac, MAX_MAC_NUM);
            break;
        case 'D':
            global.method = CMD_METHOD_D;
            str2macs(optarg, global.mac, MAX_MAC_NUM);
            break;
        case 'f':
            foreground = true;
            break;
        case 'F':
            global.method = CMD_METHOD_F;
            break;
        case 'h':
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 't':
            global.refresh_time = atoi(optarg);
            if(global.refresh_time < 1000) {
                printf("Refresh time too short\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'o':
            strncpy(global.output_file, optarg, 128);
            break;
        case 'S':
            isServer = true;
            break;
        case '1':
            foreground = true;
            break;
        case '2':
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case '3':
        {
            long b;
            b = parse_traffic_data(optarg);
            if(b < 0)
                exit(EXIT_FAILURE);
            global.max_bytes = b;
            break;
        }
        case '4':
        {
            time_t t;
            t = time_parse_date(optarg, false);
            if(t < 0)
                exit(EXIT_FAILURE);
            global.date_start = t;
            break;
        }
        case '5':
        {
            time_t t;
            t = time_parse_date(optarg, true);
            if(t < 0)
                exit(EXIT_FAILURE);
            global.date_stop = t;
            break;
        }
        case '6':
        {
            time_t t;
            t = time_parse_minutes(optarg);
            if(t < 0)
                exit(EXIT_FAILURE);
            global.daytime_start = t;
            break;
        }
        case '7':
        {
            time_t t;
            t = time_parse_minutes(optarg);
            if(t < 0)
                exit(EXIT_FAILURE);
            global.daytime_stop = t;
            break;
        }
        default:
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if(!isServer) {
        init_client(&global);
        exit(EXIT_SUCCESS);
    }

//    if(getuid() != 0) {
//        printf("Please run as root\n");
//        exit(EXIT_FAILURE);
//    }

    if(!foreground)
        daemon(0, 0);

    utasks_init();

    if(init_server() == false)
        exit(EXIT_FAILURE);

    init_pool(&arp, 10, sizeof(struct arp_info_entry));
    init_pool(&monitor, 10, sizeof(struct monitor_entry));

    tm_load_traffic_info(&monitor, global.output_file);

    if(global.refresh_time == 0)
        global.refresh_time = 3000;
    utimer_set(&refresh_timer, global.refresh_time);
    utimer_add(&refresh_timer);

    utasks_loop();
    utasks_done();

    free_pool(&monitor);
    free_pool(&arp);

    free_server();

    term_show_cursor();

    return 0;
}
