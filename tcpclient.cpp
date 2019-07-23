#include "tcpclient.h"

TcpClient::TcpClient(QObject *parent) :
    QObject(parent)
{
    m_clientSocket = new QTcpSocket();
    connect(m_clientSocket, SIGNAL(connected()), this, SLOT(connected()));
    connect(m_clientSocket, SIGNAL(disconnected()), this, SLOT(disconnected()));
}

void TcpClient::initParameters(QString ip, int port)
{
    m_ip = ip;
    m_port = port;
}

void TcpClient::connectToHost()
{
    m_clientSocket->connectToHost(m_ip, m_port);
}

void TcpClient::receiveTcpData(QByteArray data)
{
    m_clientSocket->write(data);
}

void TcpClient::connected()
{
    qDebug()<<"connected";
}

void TcpClient::disconnected()
{
    qDebug()<<"disconnected";

    m_clientSocket->connectToHost(m_ip, m_port);
}
