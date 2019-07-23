#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include "simplesniffer.h"
#include "tcpclient.h"
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private slots:
    void on_pushButton_clicked();

private:
    Ui::MainWindow *ui;
    SimpleSniffer *simpleSniffer;
    TcpClient *tcpClient;
};

#endif // MAINWINDOW_H
