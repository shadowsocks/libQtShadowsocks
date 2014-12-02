#ifndef UDPRELAY_H
#define UDPRELAY_H

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>
#include <QMap>
#include "encryptor.h"
#include "common.h"

using namespace QSS;

namespace QSS {

class UdpRelay : public QObject
{
    Q_OBJECT
public:
    explicit UdpRelay(QObject *parent = 0);

signals:
    void info(const QString &);
    void error(const QString &);

private:
    QUdpSocket *local;
    QUdpSocket *remote;
    Encryptor *encryptor;

    static QMap<CacheKey, QUdpSocket *> cache;
    static QMap<qintptr, Address> clientDescriptorToServerAddr;
    static const qint64 RecvSize = 65536;//64KB, same as shadowsocks-python (udprelay)

private slots:
    void onLocalStateChanged(QAbstractSocket::SocketState);
    void onServerUdpSocketReadyRead();
    void onClientUdpSocketReadyRead();
    void onClientDisconnected();
};

}

#endif // UDPRELAY_H
