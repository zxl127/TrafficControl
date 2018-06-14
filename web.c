#include <web.h>
#include <stdbool.h>

#define WEB_SETTING_JSON_FILE       "/tmp/web_traffic_settings"
#define TRAFFIC_OUTPUT_JSON_FILE    "/tmp/traffic_output_result"
#define TRAFFIC_CONTROL_IPTABLES_FILE    "/etc/iptables_traffic_control"

typedef struct
{
    int ctrlEnabled;
    int online;
    int clear;
    char mac[32];
    char ip[32];
    int maxTraffic;
    int uploadTraffic;
    int downloadTraffic;
    int totalTraffic;
    char startTime[32];
    char stopTime[32];
} TrafficSetting;

typedef struct
{
    int count;
    void *settings;
} TrafficControl;


int json_array_size(json_t *array)
{
    int size;
    json_t *item;

    if(!array || array->type != JSON_ARRAY)
        return 0;
    item = array->child;
    while(item)
    {
        item = item->next;
        ++size;
    }
    return size;
}
/*
TrafficControl readWebTrafficSettings(const char *file)
{
    FILE *fp;
    enum json_error error;
    json_t *doc = NULL;
    json_t *value;
    json_t *item;
    TrafficControl traffic;
    TrafficSetting *setting;

    memset(&traffic, 0, sizeof(traffic));
    fp = fopen(file, "r");
    if(!fp)
    {
        perror("Fail to open file\n");
        return traffic;
    }

    error = json_stream_parse(fp, &doc);
    if(error != JSON_OK)
    {
        printf("Parse json error\n");
        fclose(fp);
        return traffic;
    }
    fclose(fp);

    value = json_find_first_label(doc, "settings");
    if(!value)
        goto end;
    if(value->child->type != JSON_ARRAY)
        goto end;
    traffic.count = json_array_size(value->child);
    if(traffic.count == 0)
    {
        traffic.settings = NULL;
        return traffic;
    }
    else
    {
        traffic.settings = malloc(traffic.count * sizeof(TrafficSetting));
        if(traffic.settings == NULL) {
            traffic.count = 0;
            return traffic;
        }
    }

    item = value->child->child;
    setting = traffic.settings;

    while(item) {
        value = json_find_first_label(item, "maximumTraffic");
        if(!value)
            goto end;
        STRCPY_S(setting->maxTraffic, value->child->text);

        value = json_find_first_label(item, "uploadTraffic");
        if(!value)
            goto end;
        STRCPY_S(setting->uploadTraffic, value->child->text);

        value = json_find_first_label(item, "downloadTraffic");
        if(!value)
            goto end;
        STRCPY_S(setting->downloadTraffic, value->child->text);

        value = json_find_first_label(item, "totalTraffic");
        if(!value)
            goto end;
        STRCPY_S(setting->totalTraffic, value->child->text);

        value = json_find_first_label(item, "startTime");
        if(!value)
            goto end;
        STRCPY_S(setting->startTime, value->child->text);

        value = json_find_first_label(item, "stopTime");
        if(!value)
            goto end;
        STRCPY_S(setting->stopTime, value->child->text);

        value = json_find_first_label(item, "trafficControl");
        if(!value)
            goto end;
        if(value->type == JSON_TRUE)
            setting->ctrlEnabled = true;
        else
            setting->ctrlEnabled = false;

        value = json_find_first_label(item, "clear");
        if(!value)
            goto end;
        if(value->type == JSON_TRUE)
            setting->clear = true;
        else
            setting->clear = false;

        value = json_find_first_label(item, "mac");
        if(!value)
            goto end;
        STRCPY_S(setting->mac, value->child->text);

        item = item->next;
        setting = setting + sizeof(TrafficSetting);
    }

    json_free_value(&doc);
    return traffic;
end:
    if(traffic.settings)
        free(traffic.settings);
    traffic.count = 0;
    traffic.settings = NULL;
    json_free_value(&doc);
    return traffic;
}
*/
int writeTrafficInfoFile(const char *file, json_t *data)
{
    FILE *fp;
    enum json_error error;

    fp = fopen(file, "w");
    if(!fp)
    {
        perror("Fail to open file\n");
        return false;
    }

    error = json_stream_output(fp, &data);
    if(error != JSON_OK)
    {
        printf("Output json to file error\n");
        fclose(fp);
        return false;
    }
    fclose(fp);

    return true;
}

void generate_iptables_to_file(const char *file, TrafficControl traffic)
{
    int count;
    FILE *fp;
    enum json_error error;
    json_t *root, *obj, *value, *array;
    TrafficSetting *setting;

    fp = fopen(TRAFFIC_CONTROL_IPTABLES_FILE, "w");
    if(!fp)
        return;
    root = json_new_object();
    if(!root)
        goto end;

    array = json_new_array();
    if(!array)
        goto end;
    error = json_insert_pair_into_object(root, "settings", array);
    if(error != JSON_OK)
        goto end;

    setting = traffic.settings;
    count = traffic.count;
    while(count)
    {
        obj = json_new_object();
        if(!obj)
            goto end;
        value = json_new_string(setting->maxTraffic);
        if(value) {
            error = json_insert_pair_into_object(obj, "maximumTraffic", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_string(setting->uploadTraffic);
        if(value) {
            error = json_insert_pair_into_object(obj, "uploadTraffic", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_string(setting->downloadTraffic);
        if(value) {
            error = json_insert_pair_into_object(obj, "downloadTraffic", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_string(setting->totalTraffic);
        if(value) {
            error = json_insert_pair_into_object(obj, "totalTraffic", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_string(setting->startTime);
        if(value) {
            error = json_insert_pair_into_object(obj, "startTime", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_string(setting->stopTime);
        if(value) {
            error = json_insert_pair_into_object(obj, "stopTime", value);
            if(error != JSON_OK)
                goto end;
        }

        if(setting->ctrlEnabled == true)
            value = json_new_true();
        else
            value = json_new_false();
        if(value) {
            error = json_insert_pair_into_object(obj, "trafficControl", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_false();
        if(value) {
            error = json_insert_pair_into_object(obj, "clear", value);
            if(error != JSON_OK)
                goto end;
        }

        value = json_new_string(setting->mac);
        if(value) {
            error = json_insert_pair_into_object(obj, "mac", value);
            if(error != JSON_OK)
                goto end;
        }
        json_insert_child(array, obj);
        setting += sizeof(TrafficSetting);
        --count;
    }


end:
    json_free_value(&root);
}
