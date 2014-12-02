#include "connection.h"
#include "basecontroller.h"

Connection::Connection(QTcpSocket *localTcpSocket, QObject *parent) :
    QObject(parent)
{
    BaseController *c = qobject_cast<BaseController *>(parent);
    encryptor = new Encryptor(this);

    local = localTcpSocket;
    local->setParent(this);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setReadBufferSize(RecvSize);

    remote = new QTcpSocket(this);
    remote->setReadBufferSize(RecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    remote->connectToHost(c->getServerAddr(), c->getServerPort());

    socketDescriptor = local->socketDescriptor();

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked, Qt::DirectConnection);

    connect(remote, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onRemoteTcpSocketError);
    connect(remote, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(remote, &QTcpSocket::readyRead, this, &Connection::onRemoteTcpSocketReadyRead, Qt::DirectConnection);
}

void Connection::appendTcpSocket(QTcpSocket *t)
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
    QString str = QString("local socket error: ") + local->errorString();
    emit error(str);
}

void Connection::onRemoteTcpSocketError()
{
    QString str = QString("remote socket error: ") + remote->errorString();
    emit error(str);
}

void Connection::onHandshaked()
{
    QByteArray buf = local->read(256);
    if (buf.isEmpty()) {
        emit info("onHandshaked. Error! Received empty data from server.");
        return;
    }

    QByteArray response;
    response.append(char(5)).append(char(0));
    if (buf[0] != char(5)) {//reject socket v4
        emit info("a socket v4 connection was rejected.");
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
        emit error("onHandshaked2 Error! Received empty data from server.");
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
    remote->write(dataToSend);
}

void Connection::onRemoteTcpSocketReadyRead()
{
    QByteArray buf = remote->readAll();
    QByteArray dataToSend = encryptor->decrypt(buf);
    local->write(dataToSend);
}
