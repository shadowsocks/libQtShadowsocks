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
    std::string method("aes-128-cfb");
    std::string password("test");
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);

    QCOMPARE(decryptor.decrypt(encryptor.encrypt(testData)), testData);
}

void Encryptor_T::testAesGcm()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    const Cipher::CipherInfo cInfo = Cipher::cipherInfoMap.at(method);
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);

    // Test the first packet
    std::string encrypted = encryptor.encrypt(testData);
    QCOMPARE(encrypted.length(), cInfo.saltLen + 2 + cInfo.tagLen + testData.length() + cInfo.tagLen);
    std::string decrypted = decryptor.decrypt(encrypted);
    QCOMPARE(decrypted, testData);

    // The following packets don't have salts prepended
    encrypted = encryptor.encrypt(testData);
    QCOMPARE(encrypted.length(), 2 + cInfo.tagLen + testData.length() + cInfo.tagLen);
    decrypted = decryptor.decrypt(encrypted);
    QCOMPARE(decrypted, testData);
}
