TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -L$$PWD/iptables/lib -lip4tc -lxtables -liptc
INCLUDEPATH += iptables json

SOURCES += main.c \
    json/json.c \
    traffic-monitor.c \
    traffic-rules.c \
    mem-list.c \
    utask.c \
    usock.c \
    output.c \
    util.c \
    service.c

HEADERS += \
    list.h \
    iptables/iptables/internal.h \
    iptables/libiptc/ipt_kernel_headers.h \
    iptables/libiptc/libip6tc.h \
    iptables/libiptc/libiptc.h \
    iptables/libiptc/libxtc.h \
    iptables/libiptc/xtcshared.h \
    iptables/iptables.h \
    iptables/xtables-version.h \
    iptables/xtables.h \
    json/json.h \
    traffic-rules.h \
    mem-list.h \
    traffic-monitor.h \
    utask.h \
    usock.h \
    output.h \
    util.h \
    service.h \
    traffic-types.h
