#ifndef LOCAL_H
#define LOCAL_H

#include <QObject>
#include <QByteArray>
#include <QTcpSocket>
#include <QTcpServer>
#include <QList>
#include "qtshadowsocks_global.h"
#include "encryptor.h"
#include "sprofile.h"
#include "connection.h"

class QTSHADOWSOCKS_EXPORT Local : public QObject
{
    Q_OBJECT
public:
    explicit Local(QObject *parent = 0);
    ~Local();
    void setProfile(const SProfile &p);
    quint16 getServerPort();
    QString getServerAddr();

    Encryptor *encryptor;

public slots:
    void start();
    void stop();

private:
    bool running;
    QTcpServer *localTcpServer;
    SProfile profile;
    QList<Connection *> conList;

private slots:
    void onLocalTcpServerError();
    void onLocalNewConnection();
    void onConnectionDisconnected();
};

#endif // LOCAL_H
