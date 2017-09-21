#ifndef ENCRYPTOR_T_H
#define ENCRYPTOR_T_H

#include <QtTest>

class Encryptor_T : public QObject
{
    Q_OBJECT
public:
    Encryptor_T();

private Q_SLOTS:
    void selfTestEncryptDecrypt();
#ifdef USE_BOTAN2
    void testAesGcm();
    void testAesGcmUdp();
    void testAesGcmMultiChunks();
    void testAesGcmIncompleteChunks();
#endif
};

#endif // ENCRYPTOR_T_H
