#include <QtTest>
#include "crypto/cipher.h"
#include "util/common.h"

class Cipher : public QObject
{
    Q_OBJECT

public:
    Cipher() = default;

private Q_SLOTS:
    // Test md5Hash() function using test cases from
    // http://www.nsrl.nist.gov/testdata/
    void testMd5Hash();
};

void Cipher::testMd5Hash()
{
    std::string in("abc");
    QCOMPARE(QSS::Cipher::md5Hash(in), QSS::Common::stringFromHex("900150983CD24FB0D6963F7D28E17F72"));

    in = std::string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    QCOMPARE(QSS::Cipher::md5Hash(in), QSS::Common::stringFromHex("8215EF0796A20BCAAAE116D3876C664A"));
}

QTEST_MAIN(Cipher)
#include "cipher.moc"
