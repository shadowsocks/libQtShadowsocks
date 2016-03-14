#include "cipher.t.h"
#include "../lib/cipher.h"

using namespace QSS;

Cipher_T::Cipher_T()
{
}

void Cipher_T::testHmacSha1()
{
    QByteArray key = QByteArray::fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    QByteArray data("Hi There");
    QByteArray digest =
            QByteArray::fromHex("b617318655057264e28bc0b6fb378c8ef146be00");
    QCOMPARE(Cipher::hmacSha1(key, data), digest.left(10));

    key = QByteArray("Jefe");
    data = QByteArray("what do ya want for nothing?");
    digest = QByteArray::fromHex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    QCOMPARE(Cipher::hmacSha1(key, data), digest.left(10));

    key = QByteArray::fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    data = QByteArray(50, 0xdd);
    digest = QByteArray::fromHex("125d7342b9ac11cd91a39af48aa17b4f63f175d3");
    QCOMPARE(Cipher::hmacSha1(key, data), digest.left(10));
}

void Cipher_T::testMd5Hash()
{
    QByteArray in("abc");
    QCOMPARE(Cipher::md5Hash(in), QByteArray::fromHex("900150983CD24FB0D6963F7D28E17F72"));

    in = QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    QCOMPARE(Cipher::md5Hash(in), QByteArray::fromHex("8215EF0796A20BCAAAE116D3876C664A"));
}
