#include "simplesniffer.h"


SimpleSniffer::SimpleSniffer(QObject *parent) :
    QThread(parent)
{
    m_isRunning = true;
    handle = NULL;
}

SimpleSniffer::~SimpleSniffer()
{
    m_isRunning = false;
    pcap_breakloop(handle);
    quit();
    wait();
}

bool SimpleSniffer::setPcapFilter(const char *pszFilter)
{
    struct bpf_program fb;
    if (0 != pcap_compile(handle, &fb, pszFilter, 1, 0))
    {
        return false;
    }
    if (0 != pcap_setfilter(handle, &fb))
    {
        return false;
    }
    return true;
}

void SimpleSniffer::initParameters(QString pacpSrcPath, QString pacpDstPath, QString filters)
{
    m_pacpSrcPath = pacpSrcPath;
    m_pacpDstPath = pacpDstPath;
    m_filters = filters;

    QDir pacpSrcDir(m_pacpSrcPath);
    if(!pacpSrcDir.exists())
        pacpSrcDir.mkdir(m_pacpSrcPath);

    QDir pacpDstDir(m_pacpDstPath);
    if(!pacpDstDir.exists())
        pacpDstDir.mkdir(m_pacpDstPath);
}


QFileInfo SimpleSniffer::getPacpFileInfo()
{
    QFileInfo pacpFileInfo;
    QDir pacpSrcDir(m_pacpSrcPath);
    QStringList nameFilters;
    nameFilters<<"*.pcap";
    QFileInfoList fileInfoList = pacpSrcDir.entryInfoList(nameFilters, QDir::Files, QDir::Time);
    if(fileInfoList.size())
        pacpFileInfo = fileInfoList.first();

    return pacpFileInfo;
}

int SimpleSniffer::getPcapFileNum()
{
    QDir pacpSrcDir(m_pacpSrcPath);
    QStringList nameFilters;
    nameFilters<<"*.pcap";
    QFileInfoList fileInfoList = pacpSrcDir.entryInfoList(nameFilters, QDir::Files, QDir::Time);
    return fileInfoList.size();
}

bool SimpleSniffer::movePcapFile(QString pcapfile)
{
    QFileInfo fileInfo(pcapfile);
    QFile file(pcapfile);

    if(QFile::exists(m_pacpDstPath + "/" + fileInfo.fileName()))
       QFile::remove(m_pacpDstPath + "/" + fileInfo.fileName());

   return file.rename(m_pacpDstPath + "/" + fileInfo.fileName());
}




void SimpleSniffer::run()
{
    struct pcap_pkthdr *pkthdr = NULL;
    const u_char *packet = NULL;
    while(m_isRunning)
    {
        QFileInfo pacpFileInfo  = getPacpFileInfo();
        qDebug()<<pacpFileInfo.absoluteFilePath();

        if(pacpFileInfo.fileName().isEmpty())
        {
            QThread::msleep(100);
            continue;
        }

        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        handle = pcap_open_offline(pacpFileInfo.absoluteFilePath().toLocal8Bit().data(), errbuf);
        if(handle == NULL)
        {
            if(getPcapFileNum() > 1)
                movePcapFile(pacpFileInfo.absoluteFilePath());
            else
                QThread::msleep(100);

            continue;
        }

        setPcapFilter(m_filters.toStdString().data());
        int i = 0;
        while(m_isRunning)
        {
            ++i;
            int result = pcap_next_ex(handle, &pkthdr, &packet);
            if(result == 1)
            {
                DissectPacket dissectPacket;
                dissectPacket.tryDissect(pkthdr, packet);
                QByteArray tcpData = dissectPacket.getTcpData();
                if(tcpData.length())
                {
                    qDebug()<<i<<tcpData.toHex();
                    emit sendTcpData(tcpData);
                    QThread::msleep(1);
                }
            }else if(result == -2)
            {
                if(getPcapFileNum() <= 1)
                {
                    QThread::msleep(1000);
                    continue;
                }
                else
                {
                    pcap_close(handle);
                    movePcapFile(pacpFileInfo.absoluteFilePath());
                    break;
                }
            }
        }
    }
}






