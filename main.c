#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <traffic-monitor.h>


static int exitProgram = false;

struct option long_opts[] = {
    {"end-time", required_argument, NULL, '1'},
    {"foregroud", no_argument, NULL, '2'},
    {"help", no_argument, NULL, '3'},
    {"max-bytes", required_argument, NULL, '4'},
    {"start-time", required_argument, NULL, '5'},
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

int main(int argc, char **argv)
{
    int c;
    bool foreground = false;
    bool is_server = false;
    pool_t arp, monitor;

    while(1) {
        c = getopt_long(argc, argv, "A:D:fFhi:o:S", long_opts, NULL);
        if(c == EOF)
            break;
        switch (c) {
        case 'A':
            break;
        case 'D':
            break;
        case 'f':
            foreground = true;
            break;
        case 'F':
            break;
        case 'h':
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'i':
            break;
        case 'o':
            break;
        case 'S':
            is_server = true;
            break;
        case '1':
            break;
        case '2':
            break;
        case '3':
            break;
        case '4':
            break;
        case '5':
            break;
        default:
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    init_pool(&arp, 10, sizeof(struct arp_info_entry));
    init_pool(&monitor, 10, sizeof(struct monitor_entry));

    while(!exitProgram)
    {
        tm_update_traffic(&monitor);
        tm_print_traffic(&monitor);
        init_arp_cache_list(&arp);
        tm_upate_list(&monitor, &arp);
        tm_update_iptables(&monitor);

        sleep(4);
    }

    free_pool(&monitor);
    free_pool(&arp);

    return 0;
}
