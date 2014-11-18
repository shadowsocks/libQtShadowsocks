#ifndef LOCAL_H
#define LOCAL_H

#include <QObject>
#include <QByteArray>
#include <QTcpSocket>
#include <QTcpServer>
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
    QTcpServer *localTcpServer;
    QTcpSocket *localTcpSocket;
    QTcpSocket *serverTcpSocket;
    Encryptor *encryptor;
    SProfile profile;

    QByteArray local_buf;
    QByteArray server_buf;

private slots:
    void onServerTcpSocketError();
    void onServerTcpSocketReadyRead();
    void onServerConnected();
    void onLocalTcpServerError();
    void onLocalNewConnection();
    void onLocalTcpSocketError();
    void onLocalTcpSocketReadyRead();
    void onHandshaked();
    void onHandshaked2();
};

#endif // LOCAL_H
