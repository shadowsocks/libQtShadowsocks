#include "chacha.t.h"
#include "../lib/cipher.h"
#include "../lib/chacha.h"

using namespace QSS;

ChaCha_T::ChaCha_T()
{
    key = QByteArray::fromStdString(Cipher::randomIv(32));
}

void ChaCha_T::testChaCha(const QByteArray &iv)
{
    ChaCha chacha(key, iv);
    ChaCha decryptor(key, iv);
    QByteArray testString1("barfoo!");
    QCOMPARE(decryptor.update(chacha.update(testString1)), testString1);

    QByteArray testString2("$ is cheaper than £");
    QCOMPARE(decryptor.update(chacha.update(testString2)), testString2);
}

void ChaCha_T::test8ByteIV()
{
    QByteArray iv = QByteArray::fromStdString(Cipher::randomIv(8));
    testChaCha(iv);
}

void ChaCha_T::test12ByteIV()
{
    QByteArray iv = QByteArray::fromStdString(Cipher::randomIv(12));
    testChaCha(iv);
}

void ChaCha_T::referenceTest()
{
    // Test original ChaCha20 (96-byte IV)
    QByteArray testKey(32, 0);
    QByteArray testIv(8, 0);
    QByteArray testData(9, '\0');
    ChaCha chacha(testKey, testIv);
    QCOMPARE(chacha.update(testData), QByteArray::fromHex("76b8e0ada0f13d9040"));

    // Test ChaCha20-IETF
    QByteArray testIv_ietf(12, 0);
    ChaCha chacha_ietf(testKey, testIv_ietf);
    QCOMPARE(chacha_ietf.update(testData), QByteArray::fromHex("76b8e0ada0f13d9040"));
}
