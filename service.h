#ifndef SERVER_H
#define SERVER_H

#include "traffic-types.h"


#define CMD_METHOD_A    1
#define CMD_METHOD_D    2
#define CMD_METHOD_F    3



int init_server(void);
void init_client(struct traffic_setting *setting);
void free_server(void);

#endif // SERVER_H
