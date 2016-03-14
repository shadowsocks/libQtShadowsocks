#ifndef CIPHER_T_H
#define CIPHER_T_H
#include <QtTest>

class Cipher_T : public QObject
{
    Q_OBJECT

public:
    Cipher_T();

private Q_SLOTS:
    // Test hmacSha1() function using first 3 test cases from RFC 2202
    // https://tools.ietf.org/html/rfc2202
    void testHmacSha1();

    // Test md5Hash() function using test cases from
    // http://www.nsrl.nist.gov/testdata/
    void testMd5Hash();
};

#endif // CIPHER_T_H
