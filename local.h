#ifndef LOCAL_H
#define LOCAL_H

#include <QObject>
#include <QByteArray>
#include <QTcpSocket>
#include <QTcpServer>
#include <QList>
#include "qtshadowsocks_global.h"
#include "sprofile.h"
#include "connection.h"

class QTSHADOWSOCKS_EXPORT Local : public QObject
{
    Q_OBJECT
public:
    explicit Local(QObject *parent = 0);
    ~Local();
    quint16 getServerPort();
    QString getServerAddr();

public slots:
    void start(const SProfile &p);
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
