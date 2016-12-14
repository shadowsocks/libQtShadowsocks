#include "encryptor.t.h"
#include "../lib/encryptor.h"

using namespace QSS;

Encryptor_T::Encryptor_T()
{
}

const QByteArray Encryptor_T::testData = QByteArray("Hello Shadowsocks");

void Encryptor_T::selfTestEncryptDecrypt()
{
    EncryptorPrivate ep("aes-128-cfb", "test");
    Encryptor encryptor(ep);
    Encryptor decryptor(ep);

    QCOMPARE(decryptor.decrypt(encryptor.encrypt(testData)), testData);
}

void Encryptor_T::testChunkAuth()
{
    EncryptorPrivate ep("aes-128-cfb", "test");
    Encryptor encryptor(ep);
    Encryptor decryptor(ep);
    // This is to make decryptor has the same IV as encryptor does
    decryptor.decrypt(encryptor.encrypt(testData));

    QByteArray hashed = testData;
    encryptor.addChunkAuth(hashed);
    QVERIFY(decryptor.verifyExtractChunkAuth(hashed));
    QCOMPARE(hashed, testData);

    // Again!
    encryptor.addChunkAuth(hashed);
    QVERIFY(decryptor.verifyExtractChunkAuth(hashed));
    QCOMPARE(hashed, testData);
}

void Encryptor_T::testIncompleteChunkAuth()
{
    EncryptorPrivate ep("aes-128-cfb", "test");
    Encryptor encryptor(ep);
    Encryptor decryptor(ep);
    // This is to make decryptor has the same IV as encryptor does
    decryptor.decrypt(encryptor.encrypt(testData));

    QByteArray hashed1 = testData;
    QByteArray hashed2 = testData;
    encryptor.addChunkAuth(hashed1);
    encryptor.addChunkAuth(hashed2);

    // Divide two "hashed" into three parts
    QByteArray first = hashed1.mid(0, 20);
    QByteArray second = hashed1.mid(20) + hashed2.mid(0, 20);
    QByteArray third = hashed2.mid(20);

    QVERIFY(decryptor.verifyExtractChunkAuth(first));
    QVERIFY(decryptor.verifyExtractChunkAuth(second));
    QVERIFY(decryptor.verifyExtractChunkAuth(third));
    QCOMPARE(second, testData);
    QCOMPARE(third, testData);
}
