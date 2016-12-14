#include "profile.t.h"
#include "../lib/profile.h"

Profile_T::Profile_T()
{
}

void Profile_T::testConstructorEmpty()
{
    QSS::Profile p;
    QVERIFY(p.server.isEmpty());
    QCOMPARE(QString("127.0.0.1"), p.local_address);
    QVERIFY(p.method.isEmpty());
    QVERIFY(p.password.isEmpty());
    QCOMPARE(quint16(8388), p.server_port);
    QCOMPARE(quint16(1080), p.local_port);
    QCOMPARE(600, p.timeout);
    QVERIFY(!p.auth);
    QVERIFY(!p.debug);
    QVERIFY(!p.http_proxy);
}

void Profile_T::testConstructorURI()
{
    // ss://bf-cfb-auth:test@192.168.100.1:8888
    QSS::Profile p("ss://YmYtY2ZiLWF1dGg6dGVzdEAxOTIuMTY4LjEwMC4xOjg4ODg#Tést");
    QCOMPARE(QString("Tést"), p.nameTag);
    QCOMPARE(QString("192.168.100.1"), p.server);
    QCOMPARE(QString("127.0.0.1"), p.local_address);
    QCOMPARE(QString("bf-cfb"), p.method);
    QCOMPARE(QString("test"), p.password);
    QCOMPARE(quint16(8888), p.server_port);
    QCOMPARE(quint16(1080), p.local_port);
    QCOMPARE(600, p.timeout);
    QVERIFY(p.auth);
    QVERIFY(!p.debug);
    QVERIFY(!p.http_proxy);
}

void Profile_T::testToURI()
{
    QSS::Profile p;
    p.nameTag = "Tést";
    p.method = "bf-cfb";
    p.password = "test";
    p.server = "192.168.100.1";
    p.server_port = 8888;
    p.auth = false;
    QCOMPARE(QByteArray("ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Tést"), p.toURI());
}
