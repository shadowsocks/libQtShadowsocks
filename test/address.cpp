#include "types/address.h"
#include <QHostAddress>
#include <QString>
#include <QtTest>

class Address : public QObject
{
    Q_OBJECT

public:
    Address() = default;

private Q_SLOTS:
    void testConstructor1();
    void testConstructor2();
    void testAssignment();
    void testSetAddress();
    void testSetIPAddress();
    void testSetPort();
};

void Address::testConstructor1()
{
    QHostAddress ip("127.0.0.1");
    QSS::Address a("127.0.0.1", 1080), b("err", 1080);
    QCOMPARE(a.getAddress(), std::string("127.0.0.1"));
    QCOMPARE(a.getFirstIP(), ip);
    QCOMPARE(a.getPort(), uint16_t(1080));
    QVERIFY(a.isIPValid());
    QVERIFY(!b.isIPValid());
}

void Address::testConstructor2()
{
    QHostAddress ip("127.0.0.1");
    QSS::Address a(ip, 1080);
    QCOMPARE(a.getAddress(), std::string("127.0.0.1"));
    QCOMPARE(a.getFirstIP(), ip);
    QCOMPARE(a.getPort(), uint16_t(1080));
    QVERIFY(a.isIPValid());
}

void Address::testAssignment()
{
    QSS::Address a("127.0.0.1", 1080), b;
    b = a;
    QCOMPARE(a.getAddress(), b.getAddress());
    QCOMPARE(a.getFirstIP(), b.getFirstIP());
    QCOMPARE(a.getPort(), b.getPort());
    QCOMPARE(a.isIPValid(), b.isIPValid());
}

void Address::testSetAddress()
{
    QString ipStr("127.0.0.1");
    QHostAddress ip(ipStr);
    QSS::Address a;
    a.setAddress(ipStr.toStdString());
    QCOMPARE(a.getAddress(), ipStr.toStdString());
    QCOMPARE(a.getFirstIP(), ip);
    QVERIFY(a.isIPValid());
}

void Address::testSetIPAddress()
{
    QString ipStr("127.0.0.1");
    QHostAddress ip(ipStr);
    QSS::Address a;
    a.setIPAddress(ip);
    QCOMPARE(a.getAddress(), ipStr.toStdString());
    QCOMPARE(a.getFirstIP(), ip);
    QVERIFY(a.isIPValid());
}

void Address::testSetPort()
{
    QSS::Address a;
    uint16_t port = 1080;
    a.setPort(port);
    QCOMPARE(a.getPort(), port);
}

QTEST_MAIN(Address)
#include "address.moc"
