#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include "utask.h"
#include "usock.h"
#include "server.h"

void new_client_request(ufd_t *f)
{
    char buffer[1024];
    struct timeval t;

    t.tv_sec = 60;
    t.tv_usec = 0;
    for(;;) {
        int cfd = accept(f->fd, NULL, NULL);

        if (setsockopt(ufd->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof t)) {
            printf("setsockopt fail\n");
        }
        memset(buffer, 0, 1024);
        read(cfd, buffer, 1024);

    }
}

void init_server(void)
{
    ufd_t sfd;

    sfd.fd = usock(USOCK_UNIX | USOCK_SERVER, "0.0.0.0", 5277);
    sfd.handler = new_client_request;
    ufd_add(&sfd, EVENT_READ | EVENT_EDGE_TRIGGER);
}

