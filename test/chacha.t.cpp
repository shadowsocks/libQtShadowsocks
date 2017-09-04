#include "chacha.t.h"
#include "../lib/cipher.h"
#include "../lib/chacha.h"

using namespace QSS;

ChaCha_T::ChaCha_T()
{
    key = Cipher::randomIv(32);
}

void ChaCha_T::testChaCha(const std::string &iv)
{
    ChaCha chacha(key, iv);
    ChaCha decryptor(key, iv);
    std::string testString1("barfoo!");
    std::string intermed = chacha.update(testString1.data(), testString1.size());
    QCOMPARE(decryptor.update(intermed.data(), intermed.size()), testString1);

    std::string testString2("$ is cheaper than £");
    intermed = chacha.update(testString2.data(), testString2.size());
    QCOMPARE(decryptor.update(intermed.data(), intermed.size()), testString2);
}

void ChaCha_T::test8ByteIV()
{
    testChaCha(Cipher::randomIv(8));
}

void ChaCha_T::test12ByteIV()
{
    testChaCha(Cipher::randomIv(12));
}

void ChaCha_T::referenceTest()
{
    // Test original ChaCha20 (96-byte IV)
    std::string testKey(32, 0);
    std::string testIv(8, 0);
    std::string testData(9, '\0');
    ChaCha chacha(testKey, testIv);
    QCOMPARE(chacha.update(testData.data(), testData.size()),
             QByteArray::fromHex("76b8e0ada0f13d9040").toStdString());

    // Test ChaCha20-IETF
    std::string testIv_ietf(12, 0);
    ChaCha chacha_ietf(testKey, testIv_ietf);
    QCOMPARE(chacha_ietf.update(testData.data(), testData.size()),
             QByteArray::fromHex("76b8e0ada0f13d9040").toStdString());
}
