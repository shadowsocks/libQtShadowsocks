#include "address.t.h"
#include "../lib/address.h"
#include <QHostAddress>

using namespace QSS;

Address_T::Address_T()
{
}

void Address_T::testConstructor1()
{
    QHostAddress ip("127.0.0.1");
    Address a("127.0.0.1", 1080), b("err", 1080);
    QCOMPARE(a.getAddress(), std::string("127.0.0.1"));
    QCOMPARE(a.getFirstIP(), ip);
    QCOMPARE(a.getPort(), uint16_t(1080));
    QVERIFY(a.isIPValid());
    QVERIFY(!b.isIPValid());
}

void Address_T::testConstructor2()
{
    QHostAddress ip("127.0.0.1");
    Address a(ip, 1080);
    QCOMPARE(a.getAddress(), std::string("127.0.0.1"));
    QCOMPARE(a.getFirstIP(), ip);
    QCOMPARE(a.getPort(), uint16_t(1080));
    QVERIFY(a.isIPValid());
}

void Address_T::testAssignment()
{
    Address a("127.0.0.1", 1080), b;
    b = a;
    QCOMPARE(a.getAddress(), b.getAddress());
    QCOMPARE(a.getFirstIP(), b.getFirstIP());
    QCOMPARE(a.getPort(), b.getPort());
    QCOMPARE(a.isIPValid(), b.isIPValid());
}

void Address_T::testSetAddress()
{
    QString ipStr("127.0.0.1");
    QHostAddress ip(ipStr);
    Address a;
    a.setAddress(ipStr.toStdString());
    QCOMPARE(a.getAddress(), ipStr.toStdString());
    QCOMPARE(a.getFirstIP(), ip);
    QVERIFY(a.isIPValid());
}

void Address_T::testSetIPAddress()
{
    QString ipStr("127.0.0.1");
    QHostAddress ip(ipStr);
    Address a;
    a.setIPAddress(ip);
    QCOMPARE(a.getAddress(), ipStr.toStdString());
    QCOMPARE(a.getFirstIP(), ip);
    QVERIFY(a.isIPValid());
}

void Address_T::testSetPort()
{
    Address a;
    uint16_t port = 1080;
    a.setPort(port);
    QCOMPARE(a.getPort(), port);
}

void Address_T::testLookup()
{
    QSS::Address a("www.google.com", 443);
    a.lookUp([&a](bool success) {
        if (success) {
            QVERIFY(a.isIPValid());
        } else {
            QVERIFY(!a.isIPValid());
        }
    });
}

