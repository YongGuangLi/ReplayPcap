#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    simpleSniffer = new SimpleSniffer();
    tcpClient = new TcpClient();

    connect(simpleSniffer, SIGNAL(sendTcpData(QByteArray)), tcpClient, SLOT(receiveTcpData(QByteArray)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    tcpClient->initParameters(ui->lineEdit_ip->text(), ui->lineEdit_port->text().toInt());
    tcpClient->connectToHost();

    simpleSniffer->initParameters(ui->lineEdit_pcapdrc->text(), ui->lineEdit_pacpdst->text(), ui->lineEdit_filter->text());
    simpleSniffer->start();
}
