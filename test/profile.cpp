#include "types/profile.h"

#include <QString>
#include <QtTest>

class Profile : public QObject
{
    Q_OBJECT

public:
    Profile() = default;

private Q_SLOTS:
    void testConstructorEmpty();
    void testFromUri();
    void testFromUriSip002();
    void testToUri();
    void testToUriSip002();
};

void Profile::testConstructorEmpty()
{
    QSS::Profile p;
    QVERIFY(p.serverAddress().empty());
    QCOMPARE(std::string("127.0.0.1"), p.localAddress());
    QVERIFY(p.method().empty());
    QVERIFY(p.password().empty());
    QCOMPARE(uint16_t(0), p.serverPort());
    QCOMPARE(uint16_t(0), p.localPort());
    QCOMPARE(600, p.timeout());
    QVERIFY(!p.debug());
    QVERIFY(!p.httpProxy());
}

void Profile::testFromUri()
{
    // ss://bf-cfb-auth:test@192.168.100.1:8888
    QSS::Profile p = QSS::Profile::fromUri("ss://YmYtY2ZiLWF1dGg6dGVzdEAxOTIuMTY4LjEwMC4xOjg4ODg#Tést");
    QCOMPARE(std::string("Tést"), p.name());
    QCOMPARE(std::string("192.168.100.1"), p.serverAddress());
    QCOMPARE(std::string("bf-cfb-auth"), p.method());
    QCOMPARE(std::string("test"), p.password());
    QCOMPARE(uint16_t(8888), p.serverPort());
}

void Profile::testFromUriSip002()
{
    QSS::Profile p = QSS::Profile::fromUri("ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2");
    QCOMPARE(std::string("Example2"), p.name());
    QCOMPARE(std::string("192.168.100.1"), p.serverAddress());
    QCOMPARE(std::string("rc4-md5"), p.method());
    QCOMPARE(std::string("passwd"), p.password());
    QCOMPARE(uint16_t(8888), p.serverPort());
}

void Profile::testToUri()
{
    QSS::Profile p;
    p.setName("Tést");
    p.setMethod("bf-cfb");
    p.setPassword("test");
    p.setServerAddress("192.168.100.1");
    p.setServerPort(8888);
    QCOMPARE(std::string("ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Tést"), p.toUri());
}

void Profile::testToUriSip002()
{
    QSS::Profile p;
    p.setName("Example");
    p.setServerAddress("192.168.100.1");
    p.setMethod("rc4-md5");
    p.setPassword("passwd");
    p.setServerPort(8888);
    QCOMPARE(std::string("ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:8888#Example"), p.toUriSip002());
}

QTEST_MAIN(Profile)
#include "profile.moc"
