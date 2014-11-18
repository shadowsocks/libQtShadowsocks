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
    qDebug() << "local server error:" << localTcpServer->errorString();
}

void Local::onLocalTcpSocketError()
{
    qDebug() << "local socket error:" << localTcpSocket->errorString();
}

void Local::onServerTcpSocketError()
{
    qDebug() << "server socket error:" << serverTcpSocket->errorString();
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
    localTcpSocket = localTcpServer->nextPendingConnection();
    localTcpSocket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    connect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onHandshaked);
    connect(localTcpSocket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onLocalTcpSocketError);
    qDebug() << "new connection";
}

void Local::onHandshaked()
{
    local_buf = localTcpSocket->readAll();
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
    disconnect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onHandshaked);
    connect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onHandshaked2);
    localTcpSocket->write(response);
}

void Local::onHandshaked2()
{
    local_buf = localTcpSocket->readAll();
    if (local_buf.isEmpty()) {
        qDebug() << "onHandshaked2. Error! Received empty data from server.";
        return;
    }

    static char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    QByteArray response = QByteArray::fromRawData(res, sizeof(res));
    disconnect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onHandshaked2);
    connect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onLocalTcpSocketReadyRead);
    localTcpSocket->write(response);
    qDebug() << "local socket hand shaked. ready to transfer data.";
}

void Local::onLocalTcpSocketReadyRead()
{
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
