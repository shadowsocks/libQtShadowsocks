#include <QDebug>
#include "connection.h"
#include "basecontroller.h"

Connection::Connection(QTcpSocket *localTcpSocket, QObject *parent) :
    QObject(parent)
{
    BaseController *c = qobject_cast<BaseController *>(parent);
    encryptor = new Encryptor(this);
    encryptor->setup();

    local = localTcpSocket;
    local->setParent(this);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setReadBufferSize(RecvSize);

    server = new QTcpSocket(this);
    server->setReadBufferSize(RecvSize);
    server->connectToHost(c->getServerAddr(), c->getServerPort());

    socketDescriptor = local->socketDescriptor();

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked, Qt::DirectConnection);

    connect(server, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onServerTcpSocketError);
    connect(server, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(server, &QTcpSocket::readyRead, this, &Connection::onServerTcpSocketReadyRead, Qt::DirectConnection);
}

void Connection::appendSocket(QTcpSocket *t)
{
    disconnect(local, &QTcpSocket::disconnected, this, &Connection::disconnected);
    connect(local, &QTcpSocket::disconnected, local, &QTcpSocket::deleteLater);

    local = t;
    local->setParent(this);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setReadBufferSize(RecvSize);

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead, Qt::DirectConnection);
}

void Connection::onLocalTcpSocketError()
{
    qWarning() << "local socket error:" << local->errorString();
}

void Connection::onServerTcpSocketError()
{
    qWarning() << "server socket error:" << server->errorString();
}

void Connection::onHandshaked()
{
    QByteArray buf = local->read(256);
    if (buf.isEmpty()) {
        qDebug() << "onHandshaked. Error! Received empty data from server.";
        return;
    }

    QByteArray response;
    response.append(char(5)).append(char(0));
    if (buf[0] != char(5)) {//reject socket v4
        qDebug() << "a socket v4 connection was rejected.";
        response[0] = 0;
        response[1] = 91;
    }

    disconnect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked2, Qt::DirectConnection);

    local->write(response);
}

void Connection::onHandshaked2()
{
    QByteArray buf = local->read(3);
    if (buf.isEmpty()) {
        qWarning() << "onHandshaked2. Error! Received empty data from server.";
        return;
    }

    static char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    static QByteArray response = QByteArray::fromRawData(res, sizeof(res));

    disconnect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked2);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead, Qt::DirectConnection);

    local->write(response);
}

void Connection::onLocalTcpSocketReadyRead()
{
    QByteArray buf = local->readAll();
    QByteArray dataToSend = encryptor->encrypt(buf);
    server->write(dataToSend);
}

void Connection::onServerTcpSocketReadyRead()
{
    QByteArray buf = server->readAll();
    QByteArray dataToSend = encryptor->decrypt(buf);
    local->write(dataToSend);
}
