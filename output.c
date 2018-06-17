#include <stdbool.h>
#include "traffic-monitor.h"
#include "output.h"

#define TRAFFIC_OUTPUT_JSON_FILE    "/home/philips/traffic_output_result"

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
