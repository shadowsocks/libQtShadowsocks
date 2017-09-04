#include "cipher.t.h"
#include "../lib/cipher.h"

using namespace QSS;

Cipher_T::Cipher_T()
{
}

void Cipher_T::testHmacSha1()
{
    std::string key = QByteArray::fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").toStdString();
    std::string data("Hi There");
    std::string digest =
            QByteArray::fromHex("b617318655057264e28bc0b6fb378c8ef146be00").toStdString();
    QCOMPARE(Cipher::hmacSha1(key, data), digest.substr(0, 10));

    key = "Jefe";
    data = "what do ya want for nothing?";
    digest = QByteArray::fromHex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").toStdString();
    QCOMPARE(Cipher::hmacSha1(key, data), digest.substr(0, 10));

    key = QByteArray::fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").toStdString();
    data = QByteArray(50, 0xdd).toStdString();
    digest = QByteArray::fromHex("125d7342b9ac11cd91a39af48aa17b4f63f175d3").toStdString();
    QCOMPARE(Cipher::hmacSha1(key, data), digest.substr(0, 10));
}

void Cipher_T::testMd5Hash()
{
    std::string in("abc");
    QCOMPARE(Cipher::md5Hash(in), QByteArray::fromHex("900150983CD24FB0D6963F7D28E17F72").toStdString());

    in = std::string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    QCOMPARE(Cipher::md5Hash(in), QByteArray::fromHex("8215EF0796A20BCAAAE116D3876C664A").toStdString());
}
