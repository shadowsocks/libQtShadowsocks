#include "localcontroller.h"

void LocalController::start(const SProfile &p)
{
    profile = p;
    qDebug() << "initialising ciphers...";
    Encryptor::initialise(profile.method, profile.password);
    qDebug() << profile.method << "initialised.";

    tcpServer->listen(profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost, profile.local_port);
    qDebug() << "tcp server listen at port" << profile.local_port;

    running = true;
}

void LocalController::onNewConnection()
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
        connect (con, &Connection::disconnected, this, &LocalController::onConnectionDisconnected);
    }
    else {
        con->appendSocket(ts);
    }
}
