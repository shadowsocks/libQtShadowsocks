#ifndef LOCAL_H
#define LOCAL_H

#include <QObject>
#include <QByteArray>
#include <QTcpSocket>
#include "qtshadowsocks_global.h"
#include "encryptor.h"
#include "sprofile.h"

class QTSHADOWSOCKS_EXPORT Local : public QObject
{
    Q_OBJECT
public:
    explicit Local(QObject *parent = 0);
    ~Local();
    void setProfile(const SProfile &p);

public slots:
    void start();
    void stop();

private:
    bool running;
    QTcpSocket *localTcpSocket;
    QTcpSocket *serverTcpSocket;
    Encryptor *encryptor;
    SProfile profile;

    QByteArray local_buf;
    QByteArray server_buf;

private slots:
    void onLocalTcpSocketError();
    void onServerTcpSocketError();
    void onHandshaked();
    void onHandshaked2();
    void onLocalTcpSocketReadyRead();
    void onServerTcpSocketReadyRead();
    void onLocalTcpSocketStateChanged(QAbstractSocket::SocketState);
};

#endif // LOCAL_H
