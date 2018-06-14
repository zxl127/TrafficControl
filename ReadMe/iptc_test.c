#include <stdio.h>
#include <errno.h>
#include "libiptc/libiptc.h"
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <xtables.h>
#include <iptables.h>

int main( int argc , char* argv[] )
{
    char*tables = "filter";

    if (argc > 2 )
    {
        printf("toomany argument\n");
        return -1;
    }

    if (argc == 2 )
    {
        tables = argv[1];

    }

    struct iptc_handle *handle;
    const char *error = NULL;
    const char * chain = NULL;
    struct ipt_counters counters;
    const char *pol = NULL;
    const struct ipt_entry* rule;

    handle = iptc_init( tables );

    int ret = 0;

    // ret = xtables_init_all(&iptables_globals, NFPROTO_IPV4);
    // if (ret < 0 )
    // {
    //     printf("initerror\n");
    //     return -1;
    // }

    if (handle == NULL )
    {
        error = iptc_strerror(errno);
        printf("iptc_initerror:%s\n", error);
        return -1;
    }

    for (chain = iptc_first_chain(handle); chain; chain = iptc_next_chain(handle) )
    {
        printf("%s\t", chain);
        pol = iptc_get_policy(chain, &counters, handle);
        printf("%s\t", pol);
        printf("%llu\t", counters.pcnt); //经过该链的包的数量
        printf("%llu\n", counters.bcnt); //经过该链的字节数

        for (rule = iptc_first_rule(chain, handle); rule; rule = iptc_next_rule(rule, handle))
        {
            const char *target = NULL;
            target = iptc_get_target(rule, handle);

            printf("%s\t", target);
            printf("%llu\t", rule->counters.pcnt); //命中该规则的包数
            printf("%llu\t", rule->counters.bcnt); //命中该规则的字节数

            struct protoent *pro = NULL;
            pro = getprotobynumber(rule->ip.proto);

            if (pro != NULL )
            {
                printf("%s\t", pro->p_name);

            }

            if (rule->ip.iniface[0] == '\0' ) //输入网络接口默认不指定可以通过-i指定如 –I ehh0
                printf("any\t");
            else
                printf("%s\t", rule->ip.iniface);

            if (rule->ip.outiface[0] == '\0' ) //输出网络接口默认不指定可以通过-o 指定
                printf("any\t");
            else
                printf("%s\t", rule->ip.outiface);

            char addr[32] = {0};
            printf("%s\t", inet_ntop(AF_INET, &(rule->ip.src), addr, sizeof(addr)));
            printf("%s\t", inet_ntop(AF_INET, &(rule->ip.dst), addr, sizeof(addr)));
        }
    }
}