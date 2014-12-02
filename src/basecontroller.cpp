#include "basecontroller.h"

BaseController::BaseController(const Profile &p, QObject *parent) :
    QObject(parent)
{
    profile = p;

    tcpServer = new QTcpServer(this);
    udpRelay = new UdpRelay(this);

    connect(tcpServer, &QTcpServer::acceptError, this, &BaseController::onTcpServerError);
    connect(tcpServer, &QTcpServer::newConnection, this, &BaseController::onNewConnection);
}

BaseController::~BaseController()
{
    if (running) {
        stop();
    }
}

void BaseController::stop()
{
    tcpServer->close();
    running = false;
}


quint16 BaseController::getServerPort()
{
    return profile.server_port;
}

QString BaseController::getServerAddr()
{
    return profile.server;
}

quint16 BaseController::getLocalPort()
{
    return profile.local_port;
}

QHostAddress BaseController::getLocalAddr()
{
    return profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost;
}

void BaseController::onTcpServerError()
{
    QString str = QString("tcp server error: ") + tcpServer->errorString();
    emit error(str);
}

void BaseController::onNewConnection()
{
    QTcpSocket *ts = tcpServer->nextPendingConnection();
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
        connect (con, &Connection::disconnected, this, &BaseController::onConnectionDisconnected);
        connect (con, &Connection::info, this, &BaseController::info);
        connect (con, &Connection::error, this, &BaseController::error);
    }
    else {
        con->appendTcpSocket(ts);
    }
}

void BaseController::onConnectionDisconnected()
{
    Connection *con = qobject_cast<Connection *>(sender());
    if (con) {
        conList.removeOne(con);
        con->deleteLater();
        emit info("a connection closed");
        QString str = QString("current connections: ") + QString::number(conList.size());
        emit info(str);
    }
    else {
        emit error("a false sender called onConnectionDisconnected slot");
    }
}
