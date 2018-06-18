#include "json.h"
#include "util.h"
#include "output.h"
#include "traffic-types.h"

extern struct traffic_setting global;

int tm_output_traffic_info(pool_t *monitor, char *file)
{
    FILE *fp;
    mem_t *mm;
    char num[64];
    struct monitor_entry *entry;
    json_t *doc, *array, *elem, *value;
    enum json_error error;

    if(!monitor || !file || strlen(file) == 0)
        return false;

    doc = json_new_object();
    if(!doc)
        return false;

    sprintf(num, "%u", global.refresh_time);
    value = json_new_number(num);
    if(!value)
        goto end;
    error = json_insert_pair_into_object(doc, "refreshTime", value);
    if(error != JSON_OK)
        goto end;

    array = json_new_array();
    if(!array)
        goto end;
    error = json_insert_pair_into_object(doc, "entries", array);
    if(error != JSON_OK)
        goto end;

    list_for_each_entry(mm, &monitor->used_list, list) {
        entry = mm->mem;

        elem = json_new_object();
        if(!elem)
            goto end;

        if(entry->enabledCtrl)
            value = json_new_true();
        else
            value = json_new_false();
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "enabledCtrl", value);
        if(error != JSON_OK)
            goto end;

        value = json_new_string(mac2str(entry->mac));
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "mac", value);
        if(error != JSON_OK)
            goto end;

        value = json_new_string(inet_ntoa(entry->ip));
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "ip", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%llu", entry->upload_bytes);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "uploadBytes", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%llu", entry->download_bytes);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "downloadBytes", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%llu", entry->upload_packets);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "uploadPackets", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%llu", entry->download_packets);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "downloadPackets", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%u", entry->uplink);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "uplink", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%u", entry->downlink);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "downlink", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%llu", entry->max_bytes);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "maxBytes", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%u", entry->date_start);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "dateStart", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%u", entry->date_stop);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "dateStop", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%u", entry->daytime_start);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "daytimeStart", value);
        if(error != JSON_OK)
            goto end;

        sprintf(num, "%u", entry->daytime_stop);
        value = json_new_number(num);
        if(!value)
            goto end;
        error = json_insert_pair_into_object(elem, "daytimeStop", value);
        if(error != JSON_OK)
            goto end;

        error = json_insert_child(array, elem);
        if(error != JSON_OK)
            goto end;
    }

    fp = fopen(file, "w");
    if(!fp)
        goto end;

    error = json_stream_output(fp, doc);
    if(error != JSON_OK) {
        fclose(fp);
        goto end;
    }

    fclose(fp);
    json_free_value(&array);
    return true;

end:
    json_free_value(&array);
    return false;
}


int tm_load_traffic_info(pool_t *monitor, char *file)
{
    FILE *fp;
    struct monitor_entry entry;
    json_t *doc, *array, *value;
    enum json_error error;

    if(!monitor || !file || strlen(file) == 0)
        return false;

    fp = fopen(file, "r");
    if(!fp)
        return false;

    doc = NULL;
    error = json_stream_parse(fp, &doc);
    fclose(fp);
    if(error != JSON_OK)
        return false;

    value = json_find_first_label(doc, "refreshTime");
    if(!value)
        goto end;
    global.refresh_time = atoi(value->child->text);

    value = json_find_first_label(doc, "entries");
    if(!value)
        goto end;

    memset(&entry, 0, sizeof(entry));
    array = value->child->child;
    while (array) {
        value = json_find_first_label(array, "enabledCtrl");
        if(!value)
            goto end;
        if(value->child->type == JSON_FALSE) {
            array = array->next;
            continue;
        }

        entry.enabledCtrl = true;

        value = json_find_first_label(array, "mac");
        if(!value)
            goto end;
        memcpy(entry.mac, str2mac(value->child->text), ETH_ALEN);

        value = json_find_first_label(array, "uploadBytes");
        if(!value)
            goto end;
        entry.upload_bytes = atoll(value->child->text);

        value = json_find_first_label(array, "downloadBytes");
        if(!value)
            goto end;
        entry.download_bytes = atoll(value->child->text);

        value = json_find_first_label(array, "uploadPackets");
        if(!value)
            goto end;
        entry.upload_packets = atoll(value->child->text);

        value = json_find_first_label(array, "downloadPackets");
        if(!value)
            goto end;
        entry.download_packets = atoll(value->child->text);

        value = json_find_first_label(array, "maxBytes");
        if(!value)
            goto end;
        entry.max_bytes = atoll(value->child->text);

        value = json_find_first_label(array, "dateStart");
        if(!value)
            goto end;
        entry.date_start = atoi(value->child->text);

        value = json_find_first_label(array, "dateStop");
        if(!value)
            goto end;
        entry.date_stop = atoi(value->child->text);

        value = json_find_first_label(array, "daytimeStart");
        if(!value)
            goto end;
        entry.daytime_start = atoi(value->child->text);

        value = json_find_first_label(array, "daytimeStop");
        if(!value)
            goto end;
        entry.daytime_stop = atoi(value->child->text);

        monitor->add_mem(monitor, &entry, sizeof(entry));

        array = array->next;
    }

    json_free_value(&doc);
    return true;

end:
    json_free_value(&doc);
    return false;
}


