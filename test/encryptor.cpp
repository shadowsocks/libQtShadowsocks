#include "crypto/encryptor.h"
#include <QtTest>

namespace {
const std::string testData = std::string("Hello Shadowsocks");
}

class Encryptor : public QObject
{
    Q_OBJECT
public:
    Encryptor() = default;

private Q_SLOTS:
    void selfTestEncryptDecrypt();
#ifdef USE_BOTAN2
    void testAesGcm();
    void testAesGcmUdp();
    void testAesGcmMultiChunks();
    void testAesGcmIncompleteChunks();
#endif
};

void Encryptor::selfTestEncryptDecrypt()
{
    std::string method("aes-128-cfb");
    std::string password("test");
    QSS::Encryptor encryptor(method, password);
    QSS::Encryptor decryptor(method, password);

    QCOMPARE(decryptor.decrypt(encryptor.encrypt(testData)), testData);
}

#ifdef USE_BOTAN2
void Encryptor::testAesGcm()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    const Cipher::CipherInfo cInfo = Cipher::cipherInfoMap.at(method);
    QSS::Encryptor encryptor(method, password);
    QSS::Encryptor decryptor(method, password);

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

void Encryptor::testAesGcmUdp()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    const Cipher::CipherInfo cInfo = Cipher::cipherInfoMap.at(method);
    QSS::Encryptor encryptor(method, password);
    QSS::Encryptor decryptor(method, password);

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

void Encryptor::testAesGcmMultiChunks()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    QSS::Encryptor encryptor(method, password);
    QSS::Encryptor decryptor(method, password);

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

void Encryptor::testAesGcmIncompleteChunks()
{
    const std::string method("aes-256-gcm");
    const std::string password("test");
    QSS::Encryptor encryptor(method, password);
    QSS::Encryptor decryptor(method, password);

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

QTEST_MAIN(Encryptor)
#include "encryptor.moc"
