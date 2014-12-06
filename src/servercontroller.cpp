#include "servercontroller.h"

ServerController::ServerController(const Profile &p, QObject *parent) :
    BaseController(p, parent)
{
    udpRelay = new UdpRelay(false, this);
}

void ServerController::start()
{
    emit info("initialising ciphers...");
    Encryptor::initialise(profile.method, profile.password);
    QString istr = profile.method + QString(" initialised.");
    emit info(istr);

    tcpServer->listen(QHostAddress(profile.server), profile.server_port);
    QString sstr = QString("tcp server listen at port ") + QString::number(profile.local_port);
    emit info(sstr);

    running = true;
}

void ServerController::onNewConnection()
{
    QTcpSocket *ts = tcpServer->nextPendingConnection();
    Connection *con = socketDescriptorInList(ts->socketDescriptor());

    if (con == NULL) {
        con = new Connection(ts, false, this);
        conList.append(con);
        connect (con, &Connection::disconnected, this, &ServerController::onConnectionDisconnected);
        connect (con, &Connection::info, this, &ServerController::info);
        connect (con, &Connection::error, this, &ServerController::error);
        emit connectionCountChanged(conList.size());
    }
    else {
        con->appendTcpSocket(ts);
    }
}
