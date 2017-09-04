#include "encryptor.t.h"
#include "../lib/encryptor.h"

using namespace QSS;

namespace {
const std::string testData = std::string("Hello Shadowsocks");
}

Encryptor_T::Encryptor_T()
{
}

void Encryptor_T::selfTestEncryptDecrypt()
{
    QByteArray method("aes-128-cfb");
    QByteArray password("test");
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);

    QCOMPARE(decryptor.decrypt(encryptor.encrypt(testData)), testData);
}

void Encryptor_T::testChunkAuth()
{
    QByteArray method("aes-128-cfb");
    QByteArray password("test");
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);
    // This is to make decryptor has the same IV as encryptor does
    decryptor.decrypt(encryptor.encrypt(testData));

    std::string hashed = testData;
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
    QByteArray method("aes-128-cfb");
    QByteArray password("test");
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);
    // This is to make decryptor has the same IV as encryptor does
    decryptor.decrypt(encryptor.encrypt(testData));

    std::string hashed1 = testData;
    std::string hashed2 = testData;
    encryptor.addChunkAuth(hashed1);
    encryptor.addChunkAuth(hashed2);

    // Divide two "hashed" into three parts
    std::string first = hashed1.substr(0, 20);
    std::string second = hashed1.substr(20) + hashed2.substr(0, 20);
    std::string third = hashed2.substr(20);

    QVERIFY(decryptor.verifyExtractChunkAuth(first));
    QVERIFY(decryptor.verifyExtractChunkAuth(second));
    QVERIFY(decryptor.verifyExtractChunkAuth(third));
    QCOMPARE(second, testData);
    QCOMPARE(third, testData);
}
