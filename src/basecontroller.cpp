#include "basecontroller.h"

BaseController::BaseController(QObject *parent) :
    QObject(parent)
{
    tcpServer = new QTcpServer(this);

    connect(tcpServer, &QTcpServer::acceptError, this, &BaseController::onTcpServerError);
    connect(tcpServer, &QTcpServer::newConnection, this, &BaseController::onNewConnection);

    QCA::init();
}

BaseController::~BaseController()
{
    if (running) {
        stop();
    }
    QCA::deinit();
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

void BaseController::onTcpServerError()
{
    qWarning() << "tcp server error:" << tcpServer->errorString();
}

void BaseController::onConnectionDisconnected()
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
