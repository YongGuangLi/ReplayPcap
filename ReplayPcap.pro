#-------------------------------------------------
#
# Project created by QtCreator 2019-02-22T10:17:38
#
#-------------------------------------------------

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ReplayPcap
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    simplesniffer.cpp \
    tcpclient.cpp \
    dissectpacket.cpp

HEADERS  += mainwindow.h \
    simplesniffer.h \
    tcpclient.h \
    dissectpacket.h

FORMS    += mainwindow.ui

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../libpcap/lib/release/ -lpcap
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../libpcap/lib/debug/ -lpcap
else:unix: LIBS += -L$$PWD/../libpcap/lib/ -lpcap

INCLUDEPATH += $$PWD/../libpcap/include
DEPENDPATH += $$PWD/../libpcap/include

win32:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../libpcap/lib/release/pcap.lib
else:win32:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../libpcap/lib/debug/pcap.lib
else:unix: PRE_TARGETDEPS += $$PWD/../libpcap/lib/libpcap.a

INCLUDEPATH += /home/opensource/wireshark-2.0.16
LIBS += -L/usr/local/wireshark-2.0.16/lib -lwireshark


win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../glib-2.0/lib/release/ -lglib-2.0
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../glib-2.0/lib/debug/ -lglib-2.0
else:unix: LIBS += -L$$PWD/../glib-2.0/lib/ -lglib-2.0

INCLUDEPATH += $$PWD/../glib-2.0/include
DEPENDPATH += $$PWD/../glib-2.0/include
