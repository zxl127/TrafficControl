#ifndef TIMER_H
#define TIMER_H


#include "list.h"
#include <pthread.h>
#include <sys/time.h>

#define EVENT_READ              0x01
#define EVENT_WRITE             0x02
#define EVENT_EDGE_TRIGGER      0x04
#define EVENT_NONBLOCK          0x08

typedef struct u_fd ufd_t;
typedef struct u_timer utimer_t;

struct u_fd
{
    int fd;
    bool eof;
    bool error;
    bool registered;
    unsigned int events;

    void (*handler)(struct u_fd *f);
};

struct u_timer
{
    struct list_head list;

    bool waiting;
    struct timeval time;

    void (*handler)(struct u_timer *timer);
};

int ufd_add(ufd_t *fd, unsigned int events);
int ufd_delete(ufd_t *fd);
int utimer_add(utimer_t *timer);
void utimer_cancel(utimer_t *timer);
void utimer_set(utimer_t *timer, int msecs);
void utasks_init(void);
void utasks_loop(void);
void utasks_done(void);


#endif // TIMER_H
