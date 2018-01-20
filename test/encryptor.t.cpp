#include "encryptor.t.h"
#include "crypto/encryptor.h"

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

#ifdef USE_BOTAN2
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

void Encryptor_T::testAesGcmUdp()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    const Cipher::CipherInfo cInfo = Cipher::cipherInfoMap.at(method);
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);

    // Test the first packet in UDP
    std::string encrypted = encryptor.encryptAll(testData);
    QCOMPARE(encrypted.length(), cInfo.saltLen + testData.length() + cInfo.tagLen);
    std::string decrypted = decryptor.decryptAll(encrypted);
    QCOMPARE(decrypted, testData);

    // The following packets have the same structure in UDP
    encrypted = encryptor.encryptAll(testData);
    QCOMPARE(encrypted.length(), cInfo.saltLen + testData.length() + cInfo.tagLen);
    decrypted = decryptor.decryptAll(encrypted);
    QCOMPARE(decrypted, testData);
}

void Encryptor_T::testAesGcmMultiChunks()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);

    // encrypted has salt preprended
    std::string encrypted = encryptor.encrypt(std::string("Hello"));
    encrypted += encryptor.encrypt(std::string(" Bye")); // the execution order matters!
    std::string decrypted = decryptor.decrypt(encrypted);
    QCOMPARE(decrypted, std::string("Hello Bye"));

    // No salt preprended
    encrypted = encryptor.encrypt(std::string("Shadow"));
    encrypted += encryptor.encrypt(std::string("sock"));
    encrypted += encryptor.encrypt(std::string("s"));
    decrypted = decryptor.decrypt(encrypted);
    QCOMPARE(decrypted, std::string("Shadowsocks"));
}

void Encryptor_T::testAesGcmIncompleteChunks()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    Encryptor encryptor(method, password);
    Encryptor decryptor(method, password);

    // Too small for payload
    std::string encrypted = encryptor.encrypt(testData);
    std::string decrypted = decryptor.decrypt(encrypted.substr(0, 50));
    decrypted += decryptor.decrypt(encrypted.substr(50));
    QCOMPARE(decrypted, testData);

    // Too small for length
    encrypted = encryptor.encrypt(testData);
    decrypted = decryptor.decrypt(encrypted.substr(0, 2));
    decrypted += decryptor.decrypt(encrypted.substr(2));
    QCOMPARE(decrypted, testData);
}
#endif
