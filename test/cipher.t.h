#ifndef CIPHER_T_H
#define CIPHER_T_H
#include <QtTest>

class Cipher_T : public QObject
{
    Q_OBJECT

public:
    Cipher_T();

private Q_SLOTS:
    // Test md5Hash() function using test cases from
    // http://www.nsrl.nist.gov/testdata/
    void testMd5Hash();
};

#endif // CIPHER_T_H
