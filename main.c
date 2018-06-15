#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <traffic-monitor.h>


static int exitProgram = false;

struct option long_opts[] = {
    {"foregroud", no_argument, NULL, 'f'},
    {"interval", no_argument, NULL, 't'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
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
    pool_t arp, monitor;
    mem_t *mm;
    struct arp_info_entry *entry;
    struct monitor_entry *m_entry;

    /*
    while(1) {
        c = getopt_long(argc, argv, "fht", long_opts, NULL);
        if(c == EOF)
            break;
        switch (c) {
        case 'f':
            foreground = true;
            break;
        case 'h':
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 't':
            break;
        default:
            print_help(argv[0]);
            exit(EXIT_FAILURE);
            break;
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
