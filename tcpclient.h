#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <QTcpSocket>
#include <QObject>


class TcpClient : public QObject
{
    Q_OBJECT
public:
    explicit TcpClient(QObject *parent = 0);
    void initParameters(QString ip, int port);
    void connectToHost();
signals:
    
public slots:
    void receiveTcpData(QByteArray data);
    void connected();
    void disconnected();
private:
    QString m_ip;
    int m_port;
    QTcpSocket* m_clientSocket;
};

#endif // TCPCLIENT_H
