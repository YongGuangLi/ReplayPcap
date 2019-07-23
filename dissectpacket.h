#ifndef DISSECTPACKET_H
#define DISSECTPACKET_H

#include "pcap.h"
#include "epan/frame_data.h"
#include "wsutil/privileges.h"
#include "epan/epan.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>



#include <QtCore>
#include <QObject>
#include <QDebug>
#include <QMap>
#include <QStringList>
#include <QByteArray>
#include <QFile>
#include <QDateTime>
#include <QTimer>
#include <QTextCodec>
#include <QMutexLocker>

#define IP_HEADER_LEN           20
#define TCP_HEADER_LEN          20
#define UDP_HEADER_LEN          8

class DissectPacket : public QObject
{
    Q_OBJECT
public:
    explicit DissectPacket(QObject *parent = 0);
public:

    /**
    * @date      2018-10-29
    * @param     pkthdr:包头   packet:包体
    * @brief     解析报文
    * @return
    */
    void tryDissect(const struct pcap_pkthdr *pkthdr, const u_char *packet);


    void dissectIp(const struct pcap_pkthdr *pkthdr, const u_char *packet, int offset);




    void dissectTcp(const struct pcap_pkthdr *pkthdr, const u_char *packet, int offset);


    QByteArray getTcpData();

public slots:
private:
    struct ip * iphdr;
    struct tcphdr *tcp;
    struct udphdr *udp;

    int iCnt;

    QByteArray tcpDate;
private:
};

#endif // DISSECTPACKET_H
