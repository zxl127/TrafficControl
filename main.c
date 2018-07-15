/****************************************************************************
**
** Copyright (C) 2018 The * Company Ltd.
** Contact: 1150705943@qq.com
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3 as published by the Free Software
** Foundation with exceptions as appearing in the file LICENSE.GPL3-EXCEPT
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-3.0.html.
**
****************************************************************************/

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

#define VERSION     "v1.0.0"

pool_t arp, monitor;
struct traffic_setting global;


struct option long_opts[] = {
    {"foregroud", no_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {"max-bytes", required_argument, NULL, '3'},
    {"date-start", required_argument, NULL, '4'},
    {"date-stop", required_argument, NULL, '5'},
    {"daytime-start", required_argument, NULL, '6'},
    {"daytime-stop", required_argument, NULL, '7'},
    {"version", no_argument, NULL, 'v'},
    {NULL}
};

static void print_help(char *name)
{
    printf("Usage in server mode: %s -S [-f -t interval -o file]\n", name);
    printf("Usage in client mode: %s [-A -D -F] [Options]\n", name);
    printf("\n");
    printf(" Server Mode\n");
    printf(" -S                     Run in server mode\n");
    printf("\n");
    printf(" Client Operations\n");
    printf(" -A                     Add comma separated mac to traffic control table\n");
    printf(" -D                     Delete comma separated mac in traffic control table\n");
    printf(" -F                     Flush traffic control table\n");
    printf("\n");
    printf(" Options\n");
    printf(" -f, --foreground       Run in the foreground\n");
    printf(" -h, --help             Display this help text\n");
    printf(" -t                     Traffic information refresh interval(>=1000ms)\n");
    printf(" -o                     Output traffic information to file\n");
    printf(" --max-bytes            Set the maximum bytes(B/K/M/G)\n");
    printf(" --date-start           Set the start date time in YYYY[-MM[-DD[Thh[:mm[:ss]]]]]\n");
    printf(" --date-stop            Set the stop date time in YYYY[-MM[-DD[Thh[:mm[:ss]]]]]\n");
    printf(" --daytime-start        Set the start day time in hh:mm[:ss]\n");
    printf(" --daytime-stop         Set the stop day time in hh:mm[:ss]\n");
    printf(" -v, --version          Display the %s version\n", name);
}

void traffic_refresh_timeout(utimer_t *t)
{
    tm_update_traffic(&monitor);
    tm_print_traffic(&monitor);
    tm_output_traffic_info(&monitor, global.output_file);

    utimer_set(t, global.refresh_time);
    utimer_add(t);
}

void update_iptables_timeout(utimer_t *t)
{
    tm_update_arp_list(&arp);
    tm_update_monitor_list(&monitor, &arp);
    tm_update_iptables(&monitor);

    utimer_set(t, 5000);
    utimer_add(t);
}

int main(int argc, char **argv)
{
    int c;
    bool foreground = false;
    bool isServer = false;
    utimer_t refresh_timer = {.handler = traffic_refresh_timeout};
    utimer_t iptables_timer = {.handler = update_iptables_timeout};

    memset(&global, 0, sizeof(global));

    while(1) {
        c = getopt_long(argc, argv, "A:D:fFht:o:Sv", long_opts, NULL);
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
        {
            char *name = strrchr(argv[0], '/');
            name = name? (name + 1) : argv[0];
            print_help(name);
            exit(EXIT_SUCCESS);
            break;
        }
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
        case 'v':
        {
            char *name = strrchr(argv[0], '/');
            name = name? (name + 1) : argv[0];
            printf("%s %s\n", name, VERSION);
            exit(EXIT_SUCCESS);
            break;
        }
        case '3':
        {
            long long b;
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

    if(getuid() != 0) {
        printf("Please run as root\n");
        exit(EXIT_FAILURE);
    }

    if(!foreground)
        daemon(0, 0);
    else
        term_hide_cursor();

    utasks_init();

    if(init_server() == false)
        exit(EXIT_FAILURE);

    init_pool(&arp, 10, sizeof(struct arp_info_entry));
    init_pool(&monitor, 10, sizeof(struct monitor_entry));

    tm_load_traffic_info(&monitor, global.output_file);

    if(global.refresh_time == 0)
        global.refresh_time = 3000;
    utimer_set(&refresh_timer, 10);
    utimer_add(&refresh_timer);
    utimer_set(&iptables_timer, 20);
    utimer_add(&iptables_timer);

    utasks_loop();
    utasks_done();

    free_pool(&monitor);
    free_pool(&arp);

    free_server();

    term_show_cursor();

    return 0;
}
