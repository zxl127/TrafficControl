#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <fcntl.h>
#include "utask.h"
#include "usock.h"
#include "json.h"
#include "service.h"

#define TRAFFIC_CONTROL_SOCKET      "/home/philips/traffic.socket"

extern pool_t monitor;
extern struct traffic_setting global;

int response_client_request(FILE *f, int success, const char *msg)
{
    json_t *doc;
    json_t *value;
    enum json_error error;

    doc = json_new_object();
    if(!doc)
        return false;

    if(success)
        value = json_new_true();
    else
        value = json_new_false();
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "success", value);
    if(error != JSON_OK)
        goto end;

    value = json_new_string(msg);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "message", value);
    if(error != JSON_OK)
        goto end;

    error = json_stream_output(f, doc);
    if(error != JSON_OK)
        goto end;

    json_free_value(&doc);
    return true;
end:
    json_free_value(&doc);
    return false;
}

int parse_server_response(FILE *f)
{
    json_t *doc;
    json_t *value;
    enum json_error error;

    doc = NULL;
    error = json_stream_parse(f, &doc);
    if(error != JSON_OK)
        return false;

    value = json_find_first_label(doc, "success");
    if(!value)
        goto end;
//    if(value->child->type == JSON_FALSE) {
        value = json_find_first_label(doc, "message");
        if(!value)
            goto end;
        printf("%s\n", value->child->text);
//    }

    json_free_value(&doc);
    return true;
end:
    json_free_value(&doc);
    return false;
}

int send_client_request(FILE *f, struct traffic_setting *setting)
{
    char num[64], macs[MAX_MAC_NUM * 24];
    json_t *doc;
    json_t *value;
    enum json_error error;

    doc = json_new_object();
    if(!doc)
        return false;

    sprintf(num, "%d", setting->method);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "method", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%d", setting->refresh_time);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "refreshTime", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%llu", setting->max_bytes);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "maxBytes", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%d", setting->date_start);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "dateStart", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%d", setting->date_stop);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "dateStop", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%d", setting->daytime_start);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "daytimeStart", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%d", setting->daytime_stop);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "daytimeStop", value);
    if(error != JSON_OK)
        goto end;

    sprintf(num, "%d", setting->daytime_stop);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "daytimeStop", value);
    if(error != JSON_OK)
        goto end;

    macs2str(setting->mac, macs, MAX_MAC_NUM);
    value = json_new_string(macs);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "mac", value);
    if(error != JSON_OK)
        goto end;

    error = json_stream_output(f, doc);
    if(error != JSON_OK)
        goto end;

    json_free_value(&doc);
    return true;
end:
    json_free_value(&doc);
    return false;
}

int parse_client_request(FILE *f, struct traffic_setting *setting)
{
    json_t *doc;
    json_t *value;
    enum json_error error;

    doc = NULL;
    error = json_stream_parse(f, &doc);
    if(error != JSON_OK)
        return false;

    value = json_find_first_label(doc, "method");
    if(!value)
        goto end;
    setting->method = atoi(value->child->text);

    value = json_find_first_label(doc, "refreshTime");
    if(!value)
        goto end;
    setting->refresh_time = atoi(value->child->text);

    value = json_find_first_label(doc, "maxBytes");
    if(!value)
        goto end;
    setting->max_bytes = atoll(value->child->text);

    value = json_find_first_label(doc, "dateStart");
    if(!value)
        goto end;
    setting->date_start = atoi(value->child->text);

    value = json_find_first_label(doc, "dateStop");
    if(!value)
        goto end;
    setting->date_stop = atoi(value->child->text);

    value = json_find_first_label(doc, "daytimeStart");
    if(!value)
        goto end;
    setting->daytime_start = atoi(value->child->text);

    value = json_find_first_label(doc, "daytimeStop");
    if(!value)
        goto end;
    setting->daytime_stop = atoi(value->child->text);

    value = json_find_first_label(doc, "mac");
    if(!value)
        goto end;
    str2macs(value->child->text, setting->mac, MAX_MAC_NUM);

    json_free_value(&doc);
    return true;
end:
    json_free_value(&doc);
    return false;
}

void apply_client_settings(struct traffic_setting *setting, pool_t *monitor)
{
    int i;
    struct monitor_entry entry;

    memset(&entry, 0, sizeof(entry));

    entry.date_start = setting->date_start;
    entry.date_stop = setting->date_stop;
    entry.daytime_start = setting->daytime_start;
    entry.daytime_stop = setting->daytime_stop;
    entry.max_bytes = setting->max_bytes;
    switch (setting->method) {
    case CMD_METHOD_A:
        for(i = 0; i < MAX_MAC_NUM; ++i) {
            if(zero_mac(setting->mac[i]))
                break;
            memcpy(entry.mac, setting->mac[i], ETH_ALEN);
            tm_add_entry(monitor, &entry);
        }
        break;
    case CMD_METHOD_D:
        for(i = 0; i < MAX_MAC_NUM; ++i) {
            if(zero_mac(setting->mac[i]))
                break;
            memcpy(entry.mac, setting->mac[i], ETH_ALEN);
            tm_del_entry(monitor, &entry);
        }
        break;
    case CMD_METHOD_F:
        monitor->del_all(monitor);
        break;
    default:
        printf("Invalid method\n");
        break;
    }
    if(setting->refresh_time >= 1000)
        global.refresh_time = setting->refresh_time;
}

void process_client_request(ufd_t *f)
{
    FILE *fp;
    struct traffic_setting setting;

    fp = fdopen(f->fd, "r+");
    if(!fp)
        goto end;

    if(parse_client_request(fp, &setting) == false) {
        response_client_request(fp, false, "Parse settings error");
    } else {
        apply_client_settings(&setting, &monitor);
        response_client_request(fp, true, "Apply settings success");
    }
end:
    ufd_delete(f);
    fclose(fp);
    free(f);
}

static void new_client_request(ufd_t *f)
{
    ufd_t *ufd;
    struct timeval t;

    t.tv_sec = 10;
    t.tv_usec = 0;

    for(;;) {
        int cfd = accept(f->fd, NULL, NULL);
        if(cfd < 0)
            break;

        if (setsockopt(f->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t)) {
            printf("setsockopt fail\n");
        }

        ufd = calloc(1, sizeof(ufd_t));
        if(!ufd) {
            close(cfd);
            continue;
        }
        ufd->fd = cfd;
        ufd->handler = process_client_request;
        ufd_add(ufd, EVENT_READ | EVENT_NONBLOCK);
    }
}

int init_server(void)
{
    static ufd_t sfd;

    unlink(TRAFFIC_CONTROL_SOCKET);
    if(access(TRAFFIC_CONTROL_SOCKET, F_OK) == 0) {
        printf("Server is running\n");
        return false;
    }

    sfd.fd = usock(USOCK_UNIX | USOCK_SERVER, TRAFFIC_CONTROL_SOCKET, NULL);
    if(sfd.fd < 0) {
        printf("Init server error\n");
        return false;
    }
    sfd.handler = new_client_request;
    ufd_add(&sfd, EVENT_READ | EVENT_NONBLOCK);
    return true;
}

void init_client(struct traffic_setting *setting)
{
    int fd;
    FILE *fp;
    struct timeval t;

    if(access(TRAFFIC_CONTROL_SOCKET, F_OK) != 0) {
        printf("No server running\n");
        return;
    }

    fd = usock(USOCK_UNIX, TRAFFIC_CONTROL_SOCKET, NULL);
    if(fd < 0) {
        printf("Init client error\n");
        return;
    }

    t.tv_sec = 10;
    t.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t)) {
        printf("setsockopt fail\n");
    }

    fp = fdopen(fd, "r+");
    if(!fp) {
        printf("fdopen error\n");
        close(fd);
        return;
    }

    send_client_request(fp, setting);
    parse_server_response(fp);
    fclose(fp);
}

void free_server(void)
{
    unlink(TRAFFIC_CONTROL_SOCKET);
}
