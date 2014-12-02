#ifndef COMMON_H
#define COMMON_H

#include <QByteArray>
#include <QHostAddress>

namespace QSS {

class Common
{
public:
    static void parseHeader(const QByteArray &data, QHostAddress &addr, quint16 &port, int &length);
    static const int ADDRTYPE_IPV4 = 1;
    static const int ADDRTYPE_IPV6 = 4;
    static const int ADDRTYPE_HOST = 3;
};

class Address
{
public:
    Address(const QHostAddress &a = QHostAddress(), const quint16 &p = 0) : addr(a), port(p) {}
    QHostAddress addr;
    quint16 port;

    Address& operator=(const Address &o) {
        this->addr = o.addr;
        this->port = o.port;
        return *this;
    }

    inline bool operator<(const Address &o) const {
        if (this->addr.toIPv4Address() == o.addr.toIPv4Address()) {
            return this->port < o.port;
        }
        else {
            return this->addr.toIPv4Address() < o.addr.toIPv4Address();
        }
    }

    inline bool operator==(const Address &o) const {
        return (this->addr.toIPv4Address() == o.addr.toIPv4Address()) && (this->port == o.port);
    }
};

class CacheKey
{
public:
    CacheKey(const QHostAddress &ra = QHostAddress(), const quint16 &rp = 0, const QHostAddress &da = QHostAddress(), const quint16 &dp = 0) : r(ra, rp), d(da, dp) {}
    Address r;
    Address d;

    inline bool operator<(const CacheKey &o) const {
        if (this->r == o.r) {
            return this->d < o.d;
        }
        else {
            return this->r < o.r;
        }
    }
};

}

#endif // COMMON_H
