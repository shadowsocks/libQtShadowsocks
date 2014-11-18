#include <QDebug>
#include <QHostAddress>
#include "local.h"

Local::Local(QObject *parent) :
    QObject(parent)
{
    localTcpSocket = new QTcpSocket(this);//local means *local* server
    serverTcpSocket = new QTcpSocket(this);//server means *remote* server
    encryptor = new Encryptor(this);
    localTcpSocket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    localTcpSocket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    connect(localTcpSocket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onLocalTcpSocketError);
    connect(localTcpSocket, &QAbstractSocket::stateChanged, this, &Local::onLocalTcpSocketStateChanged);
    connect(serverTcpSocket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onServerTcpSocketError);
    connect(serverTcpSocket, &QTcpSocket::readyRead, this, &Local::onServerTcpSocketReadyRead);
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

void Local::onLocalTcpSocketError()
{
    qDebug() << "local error:" << localTcpSocket->errorString();
}

void Local::onServerTcpSocketError()
{
    qDebug() << "server error:" << serverTcpSocket->errorString();
}

void Local::start()
{
    if (profile.shareOverLAN) {
        qDebug() << "binding local on" << QHostAddress(QHostAddress::Any).toString();
        localTcpSocket->bind(QHostAddress::Any, profile.local_port, QAbstractSocket::ReuseAddressHint);
    }
    else {
        qDebug() << "binding local on" << QHostAddress(QHostAddress::LocalHost).toString();
        localTcpSocket->bind(QHostAddress::LocalHost, profile.local_port, QAbstractSocket::ReuseAddressHint);
    }
    qDebug() << "local listening at port" << profile.local_port;

    connect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onHandshaked);

    qDebug() << "connecting to" << profile.server << "at port" << profile.server_port;
    serverTcpSocket->connectToHost(profile.server, profile.server_port);
    running = true;
}

void Local::stop()
{
    localTcpSocket->close();
    serverTcpSocket->close();
    disconnect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onLocalTcpSocketReadyRead);
    running = false;
}

void Local::onHandshaked()
{
    local_buf = localTcpSocket->readAll();
    if (local_buf.isEmpty()) {
        qDebug() << "Error! Received empty data from server.";
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
        qDebug() << "Error! Received empty data from server.";
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

void Local::onLocalTcpSocketStateChanged(QAbstractSocket::SocketState stat)
{
    qDebug() << "local socket state changed to" << stat;
}
