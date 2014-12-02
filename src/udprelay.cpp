#include "udprelay.h"
#include "basecontroller.h"

UdpRelay::UdpRelay(QObject *parent) :
    QObject(parent)
{
    BaseController *c = qobject_cast<BaseController *>(parent);
    encryptor = new Encryptor(this);
    local = new QUdpSocket(this);
    remote = new QUdpSocket(this);

    connect(local, &QUdpSocket::stateChanged, this, &UdpRelay::onLocalStateChanged);
    connect(local, &QUdpSocket::readyRead, this, &UdpRelay::onServerUdpSocketReadyRead);
    //connect(remote, &QUdpSocket::readyRead, this, &UdpRelay::onRemoteUdpSocketReadyRead);

    local->bind(c->getLocalAddr(), c->getLocalPort(), QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    local->setReadBufferSize(RecvSize);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    remote->connectToHost(c->getServerAddr(), c->getServerPort());
    remote->setReadBufferSize(RecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
}

//static member
QMap<CacheKey, QUdpSocket *> UdpRelay::cache;
QMap<qintptr, Address> UdpRelay::clientDescriptorToServerAddr;

void UdpRelay::onLocalStateChanged(QAbstractSocket::SocketState s)
{
    qDebug() << "local udp socket state changed to" << s;
}

void UdpRelay::onServerUdpSocketReadyRead()
{
    QUdpSocket *server = qobject_cast<QUdpSocket *>(sender());
    if (server->pendingDatagramSize() > RecvSize) {
        qDebug() << "datagram is too large. discarded.";
        return;
    }

    QByteArray data;
    data.resize(server->pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    server->readDatagram(data.data(), RecvSize, &r_addr, &r_port);

    if (static_cast<int> (data[2]) != 0) {
        qDebug() << "drop a message since frag is not 0";
        return;
    }
    data.remove(0, 2);

    QHostAddress dest_addr;
    quint16 dest_port;
    int header_length = 0;

    Common::parseHeader(data, dest_addr, dest_port, header_length);
    if (header_length == 0) {
        return;
    }

    CacheKey key(r_addr, r_port, dest_addr, dest_port);
    QUdpSocket *client = cache.value(key, NULL);
    if (client == NULL) {
        client = new QUdpSocket(this);
        client->setReadBufferSize(RecvSize);
        client->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        cache.insert(key, client);
        clientDescriptorToServerAddr.insert(client->socketDescriptor(), key.r);
        connect(client, &QUdpSocket::readyRead, this, &UdpRelay::onClientUdpSocketReadyRead);
        connect(client, &QUdpSocket::disconnected, this, &UdpRelay::onClientDisconnected);
    }

    data = encryptor->encryptAll(data);

    client->writeDatagram(data, remote->peerAddress(), remote->peerPort());
}

void UdpRelay::onClientUdpSocketReadyRead()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (sock == NULL) {
        qCritical() << "Fatal. A false object calling onClientUdpSocketReadyRead.";
        return;
    }

    if (sock->pendingDatagramSize() > RecvSize) {
        qDebug() << "datagram is too large. discarded.";
        return;
    }

    QByteArray data;
    data.resize(sock->pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    sock->readDatagram(data.data(), RecvSize, &r_addr, &r_port);

    data = encryptor->decryptAll(data);
    if (data.isEmpty()) {
        return;
    }

    QHostAddress d_addr;
    quint16 d_port;
    int header_length = 0;

    Common::parseHeader(data, d_addr, d_port, header_length);
    if (header_length == 0) {
        return;
    }

    QByteArray response = QByteArray("\x00\x00\x00") + data;
    Address clientAddress = clientDescriptorToServerAddr.value(sock->socketDescriptor());
    if (clientAddress.port != 0) {
        remote->writeDatagram(response, clientAddress.addr, clientAddress.port);
    }
    //else this packet is from somewhere else we know
    //simply drop that packet
}

void UdpRelay::onClientDisconnected()
{
    QUdpSocket *client = qobject_cast<QUdpSocket *>(sender());
    if (client == NULL) {
        qCritical() << "Fatal. A false object calling onClientDisconnected.";
        return;
    }
    cache.remove(cache.key(client));
    clientDescriptorToServerAddr.remove(client->socketDescriptor());
    client->deleteLater();
}
