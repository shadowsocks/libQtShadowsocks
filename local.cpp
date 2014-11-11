#include <QDebug>
#include <QHostAddress>
#include "local.h"

Local::Local(QObject *parent) :
    QObject(parent)
{
    localTcpSocket = new QTcpSocket(this);
    serverTcpSocket = new QTcpSocket(this);
    encryptor = new Encryptor(this);
    localTcpSocket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    localTcpSocket->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    connect(localTcpSocket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onLocalTcpSocketError);
    connect(serverTcpSocket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Local::onServerTcpSocketError);
    connect(serverTcpSocket, &QTcpSocket::readyRead, this, &Local::onServerTcpSocketReadyRead);
}

void Local::setProfile(const SProfile &p)
{
    profile = p;
    encryptor->setup(profile.method, profile.password);
}

void Local::onLocalTcpSocketError()
{
    qDebug() << localTcpSocket->errorString();
}

void Local::onServerTcpSocketError()
{
    qDebug() << serverTcpSocket->errorString();
}

void Local::start()
{
    if (profile.shareOverLAN) {
        localTcpSocket->bind(QHostAddress::Any, profile.local_port, QAbstractSocket::ReuseAddressHint);
    }
    else {
        localTcpSocket->bind(QHostAddress::LocalHost, profile.local_port, QAbstractSocket::ReuseAddressHint);
    }

    connect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onHandshaked);
    serverTcpSocket->connectToHost(profile.server, profile.server_port);
}

void Local::stop()
{
    localTcpSocket->close();
    serverTcpSocket->close();
    disconnect(localTcpSocket, &QTcpSocket::readyRead, this, &Local::onLocalTcpSocketReadyRead);
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
