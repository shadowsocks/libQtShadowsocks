#include <QDebug>
#include <QHostAddress>
#include "local.h"

Local::Local(QObject *parent) :
    QObject(parent)
{
    localTcpServer = new QTcpServer(this);//local means local *server*
    serverTcpSocket = new QTcpSocket(this);//server means *remote* server
    encryptor = new Encryptor(this);

    connect(localTcpServer, &QTcpServer::acceptError, this, &Local::onLocalTcpServerError);
    connect(localTcpServer, &QTcpServer::newConnection, this, &Local::onLocalNewConnection);
    connect(serverTcpSocket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onServerTcpSocketError);
    connect(serverTcpSocket, &QTcpSocket::readyRead, this, &Local::onServerTcpSocketReadyRead);
    connect(serverTcpSocket, &QTcpSocket::connected, this, &Local::onServerConnected);

    localTcpServer->setMaxPendingConnections(1);//for easy debug.
}

Local::~Local()
{
    if (running) {
        stop();
    }
}

void Local::setProfile(const SProfile &p)
{
    profile = p;
    qDebug() << "initialising ciphers...";
    encryptor->setup(profile.method, profile.password);
}

void Local::onLocalTcpServerError()
{
    qWarning() << "local server error:" << localTcpServer->errorString();
}

void Local::onLocalTcpSocketError()
{
    QTcpSocket *ts = qobject_cast<QTcpSocket *>(sender());
    if (ts) {
        qWarning() << "local socket error:" << ts->errorString();
    }
    else {
        qCritical() << "a false sender called onLocalTcpSocketError slot function.";
    }
}

void Local::onServerTcpSocketError()
{
    qWarning() << "server socket error:" << serverTcpSocket->errorString();
}

void Local::start()
{
    localTcpServer->listen(profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost, profile.local_port);
    qDebug() << "local server listen at port" << profile.local_port;

    qDebug() << "connecting to remote server" << profile.server;
    serverTcpSocket->connectToHost(profile.server, profile.server_port);

    running = true;
}

void Local::stop()
{
    localTcpServer->close();
    serverTcpSocket->close();
    running = false;
}

void Local::onLocalNewConnection()
{
    QTcpSocket *ts = localTcpServer->nextPendingConnection();
    ts->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    connect(ts, &QTcpSocket::readyRead, this, &Local::onHandshaked);
    connect(ts, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onLocalTcpSocketError);
    connect(ts, &QTcpSocket::disconnected, ts, &QTcpSocket::deleteLater);
    qDebug() << "new connection";
}

void Local::onHandshaked()
{
    QTcpSocket *ts = qobject_cast<QTcpSocket *>(sender());
    if (!ts) {
        qCritical() << "a false sender called onHandshaked slot function.";
        return;
    }

    local_buf = ts->read(256);
    if (local_buf.isEmpty()) {
        qDebug() << "onHandshaked. Error! Received empty data from server.";
        return;
    }

    QByteArray response;
    response.append(char(5)).append(char(0));
    if (local_buf[0] != char(5)) {//reject socket v4
        qDebug() << "a socket v4 connection was rejected.";
        response[0] = 0;
        response[1] = 91;
    }
    disconnect(ts, &QTcpSocket::readyRead, this, &Local::onHandshaked);
    connect(ts, &QTcpSocket::readyRead, this, &Local::onHandshaked2);
    ts->write(response);
}

void Local::onHandshaked2()
{
    QTcpSocket *ts = qobject_cast<QTcpSocket *>(sender());
    if (!ts) {
        qCritical() << "a false sender called onHandshaked2 slot function.";
        return;
    }

    local_buf = ts->read(3);
    if (local_buf.isEmpty()) {
        qWarning() << "onHandshaked2. Error! Received empty data from server.";
        return;
    }

    static char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    QByteArray response = QByteArray::fromRawData(res, sizeof(res));
    disconnect(ts, &QTcpSocket::readyRead, this, &Local::onHandshaked2);
    connect(ts, &QTcpSocket::readyRead, this, &Local::onLocalTcpSocketReadyRead);
    ts->write(response);
    qDebug() << "local socket hand shaked. ready to transfer data.";
}

void Local::onLocalTcpSocketReadyRead()
{
    localTcpSocket = qobject_cast<QTcpSocket *>(sender());
    if (!localTcpSocket) {
        qCritical() << "a false sender called onLocalTcpSocketReadyRead slot function.";
        return;
    }

    local_buf = localTcpSocket->readAll();
    QByteArray dataToSend = encryptor->encrypt(local_buf);
    serverTcpSocket->write(dataToSend);
}

void Local::onServerTcpSocketReadyRead()
{
    server_buf = serverTcpSocket->readAll();
    QByteArray dataToSend = encryptor->decrypt(server_buf);
    localTcpSocket->write(dataToSend);
}

void Local::onServerConnected()
{
    qDebug() << "connected to remote server" << serverTcpSocket->peerAddress() << "at port" << serverTcpSocket->peerPort();
}
