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
    void referenceTest();

private:
    std::string key;
    void testChaCha(const std::string &iv);
};

#endif // CHACHA_T_H
