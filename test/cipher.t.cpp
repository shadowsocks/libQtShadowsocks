#include "cipher.t.h"
#include "../lib/cipher.h"
#include "../lib/common.h"

using namespace QSS;

Cipher_T::Cipher_T()
{
}

void Cipher_T::testMd5Hash()
{
    std::string in("abc");
    QCOMPARE(Cipher::md5Hash(in), Common::stringFromHex("900150983CD24FB0D6963F7D28E17F72"));

    in = std::string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    QCOMPARE(Cipher::md5Hash(in), Common::stringFromHex("8215EF0796A20BCAAAE116D3876C664A"));
}
