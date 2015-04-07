#include "addresstester.h"

using namespace QSS;

AddressTester::AddressTester(const QHostAddress &_address, const quint16 &_port, QObject *parent) :
    QObject(parent),
    address(_address),
    port(_port)
{
    socket = new QTcpSocket(this);
    timer = new QTimer(this);
    timer->setSingleShot(true);
    time = QTime::currentTime();

    connect(timer, &QTimer::timeout, this, &AddressTester::onTimeout);
    connect(socket, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>(&QTcpSocket::error), this, &AddressTester::onSocketError);
    connect(socket, &QTcpSocket::connected, this, &AddressTester::onConnected);
}

AddressTester::~AddressTester()
{
}

void AddressTester::startLagTest(int timeout)
{
    time = QTime::currentTime();
    timer->start(timeout);
    socket->connectToHost(address, port);
}

void AddressTester::onTimeout()
{
    socket->disconnectFromHost();
    emit lagTestFinished(-1);
}

void AddressTester::onSocketError()
{
    emit testErrorString(socket->errorString());
    onTimeout();
}

void AddressTester::onConnected()
{
    timer->stop();
    emit lagTestFinished(time.msecsTo(QTime::currentTime()));
}
