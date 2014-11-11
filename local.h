#ifndef LOCAL_H
#define LOCAL_H

#include <QObject>
#include <QByteArray>
#include <QTcpSocket>
#include "encryptor.h"
#include "sprofile.h"

class Local : public QObject
{
    Q_OBJECT
public:
    explicit Local(QObject *parent = 0);
    void setProfile(const SProfile &p);

signals:

public slots:
    void start();
    void stop();

private:
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
};

#endif // LOCAL_H
