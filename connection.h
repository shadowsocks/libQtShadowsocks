#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include "encryptor.h"

class Connection : public QObject
{
    Q_OBJECT
public:
    explicit Connection(QTcpSocket *localTcpSocket, QObject *parent = 0);

    qintptr socketDescriptor;
    static const qint64 RecvSize = 16384;

public slots:
    void appendSocket(QTcpSocket *);

signals:
    void disconnected();

private:
    QTcpSocket *local;
    QTcpSocket *server;
    Encryptor *encryptor;

private slots:
    void onServerTcpSocketError();
    void onServerTcpSocketReadyRead();
    void onServerConnected();
    void onLocalTcpSocketError();
    void onLocalTcpSocketReadyRead();
    void onHandshaked();
    void onHandshaked2();
};

#endif // CONNECTION_H
