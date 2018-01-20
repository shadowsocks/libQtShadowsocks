#include "crypto/cipher.h"
#include "crypto/chacha.h"
#include "util/common.h"
#include <QtTest>

class ChaCha : public QObject
{
    Q_OBJECT

public:
    ChaCha();

private Q_SLOTS:
    void test8ByteIV();
    void test12ByteIV();
    void referenceTest();

private:
    std::string key;
    void testChaCha(const std::string &iv);
};

ChaCha::ChaCha()
{
    key = QSS::Cipher::randomIv(32);
}

void ChaCha::testChaCha(const std::string &iv)
{
    QSS::ChaCha chacha(key, iv);
    QSS::ChaCha decryptor(key, iv);
    std::string testString1("barfoo!");
    std::string intermed = chacha.update(testString1);
    QCOMPARE(decryptor.update(intermed), testString1);

    std::string testString2("$ is cheaper than £");
    intermed = chacha.update(testString2);
    QCOMPARE(decryptor.update(intermed), testString2);
}

void ChaCha::test8ByteIV()
{
    testChaCha(QSS::Cipher::randomIv(8));
}

void ChaCha::test12ByteIV()
{
    testChaCha(QSS::Cipher::randomIv(12));
}

void ChaCha::referenceTest()
{
    // Test original ChaCha20 (96-byte IV)
    std::string testKey(32, 0);
    std::string testIv(8, 0);
    std::string testData(9, '\0');
    QSS::ChaCha chacha(testKey, testIv);
    QCOMPARE(chacha.update(testData),
             QSS::Common::stringFromHex("76b8e0ada0f13d9040"));

    // Test ChaCha20-IETF
    std::string testIv_ietf(12, 0);
    QSS::ChaCha chacha_ietf(testKey, testIv_ietf);
    QCOMPARE(chacha_ietf.update(testData),
             QSS::Common::stringFromHex("76b8e0ada0f13d9040"));
}

QTEST_MAIN(ChaCha)
#include "chacha.moc"
