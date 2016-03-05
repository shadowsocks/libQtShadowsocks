#include "chacha.t.h"
#include "../lib/cipher.h"
#include "../lib/chacha.h"

using namespace QSS;

ChaCha_T::ChaCha_T()
{
    key = Cipher::randomIv(32);
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
    QByteArray iv  = Cipher::randomIv(8);
    testChaCha(iv);
}

void ChaCha_T::test12ByteIV()
{
    QByteArray iv  = Cipher::randomIv(12);
    testChaCha(iv);
}
