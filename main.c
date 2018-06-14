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
    */
#if 1
    init_pool(&arp, 10, sizeof(struct arp_info_entry));
    init_pool(&monitor, 10, sizeof(struct monitor_entry));

    while(!exitProgram)
    {
        arp.del_all(&arp);
        tm_update_traffic(&monitor);
        init_arp_cache_list(&arp);
//        printf("########arp table########\n");
        list_for_each_entry(mm, &arp.used_list, list) {
            entry = mm->mem;
//            printf("%s\t", inet_ntoa(entry->ip));
//            printf("%s\n", mac2str(entry->mac));
        }
        tm_upate_list(&monitor, &arp);
        printf("########monitor table########\n");
        list_for_each_entry(mm, &monitor.used_list, list) {
            m_entry = mm->mem;
            printf("%s\t", inet_ntoa(m_entry->ip));
            printf("%s\t", mac2str(m_entry->mac));
            printf("%d\t", m_entry->download_bytes);
            printf("%d\n", m_entry->upload_bytes);
        }
        tm_update_iptables(&monitor);

        sleep(4);
    }

    free_pool(&monitor);
    free_pool(&arp);
#endif
//    test_counter();

    return 0;
}
