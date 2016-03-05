#ifndef CHACHA_T_H
#define CHACHA_T_H
#include <QtTest>

class ChaCha_T : public QObject
{
    Q_OBJECT

public:
    ChaCha_T();

private Q_SLOTS:
    void test8ByteIV();
    void test12ByteIV();

private:
    QByteArray key;
    void testChaCha(const QByteArray &iv);
};

#endif // CHACHA_T_H
