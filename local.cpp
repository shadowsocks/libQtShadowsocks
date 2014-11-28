#include <QDebug>
#include <QHostAddress>
#include "local.h"
#include "encryptor.h"

Local::Local(QObject *parent) :
    QObject(parent)
{
    localTcpServer = new QTcpServer(this);//local means local *server*

    connect(localTcpServer, &QTcpServer::acceptError, this, &Local::onLocalTcpServerError);
    connect(localTcpServer, &QTcpServer::newConnection, this, &Local::onLocalNewConnection);

    QCA::init();
}

Local::~Local()
{
    if (running) {
        stop();
    }
    QCA::deinit();
}

void Local::start(const SProfile &p)
{
    profile = p;
    qDebug() << "initialising ciphers...";
    Encryptor::initialise(profile.method, profile.password);
    qDebug() << profile.method << "initialised.";

    localTcpServer->listen(profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost, profile.local_port);
    qDebug() << "local server listen at port" << profile.local_port;

    running = true;
}

void Local::stop()
{
    localTcpServer->close();
    running = false;
}

quint16 Local::getServerPort()
{
    return profile.server_port;
}

QString Local::getServerAddr()
{
    return profile.server;
}

void Local::onLocalNewConnection()
{
    QTcpSocket *ts = localTcpServer->nextPendingConnection();
    qintptr tsd = ts->socketDescriptor();

    Connection *con = NULL;

    foreach (Connection *c, conList) {
        if (tsd == c->socketDescriptor) {
            con = c;
        }
    }

    if (con == NULL) {
        con = new Connection(ts, this);
        conList.append(con);
        connect (con, &Connection::disconnected, this, &Local::onConnectionDisconnected);
    }
    else {
        con->appendSocket(ts);
    }
}

void Local::onLocalTcpServerError()
{
    qWarning() << "local server error:" << localTcpServer->errorString();
}

void Local::onConnectionDisconnected()
{
    Connection *con = qobject_cast<Connection *>(sender());
    if (con) {
        conList.removeOne(con);
        con->deleteLater();
        qDebug() << "a connection closed";
        qDebug() << "current connections: " << conList.size();
    }
    else {
        qCritical() << "a false sender called onConnectionDisconnected slot";
    }
}
