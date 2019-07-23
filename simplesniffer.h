#ifndef SIMPLESNIFFER_H
#define SIMPLESNIFFER_H

#include "pcap.h"
#include "dissectpacket.h"

#include <QObject>
#include <QThread>
#include <QDebug>
#include <QList>
#include <QDir>



class SimpleSniffer : public QThread
{
    Q_OBJECT
public:
    explicit SimpleSniffer(QObject *parent = 0);
    ~SimpleSniffer();

    bool setPcapFilter(const char* pszFilter);


    void initParameters(QString pacpSrcPath, QString pacpDstPath, QString filters);

    QFileInfo getPacpFileInfo();

    int getPcapFileNum();

    bool movePcapFile(QString pcapfile);
    /**
    * @date      2018-10-25
    * @param
    * @return
    * @brief     抓包   函数pcap_next_ex  返回1:报文读取成功     返回-2：文件最后一个报文
    */
    void run();

signals:
    void sendTcpData(QByteArray data);
private:
    pcap_t *handle;              /* 会话句柄 */

private:
    bool m_isRunning;
    QString m_pacpSrcPath;
    QString m_pacpDstPath;
    QString m_filters;               //src host 192.168.188.108 and dst port 8801


};

#endif // SIMPLESNIFFER_H
