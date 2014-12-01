#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include "encryptor.h"

using namespace QSS;

namespace QSS {

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
    void info(const QString &);
    void error(const QString &);

private:
    QTcpSocket *local;
    QTcpSocket *remote;
    Encryptor *encryptor;

private slots:
    void onRemoteTcpSocketError();
    void onRemoteTcpSocketReadyRead();
    void onLocalTcpSocketError();
    void onLocalTcpSocketReadyRead();
    void onHandshaked();
    void onHandshaked2();
};

}
#endif // CONNECTION_H
