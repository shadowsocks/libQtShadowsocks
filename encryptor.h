#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <QObject>
#include <QVector>
#include <QMap>
#include <QCryptographicHash>
#include <QtCrypto/qca.h>

class Encryptor : public QObject
{
    Q_OBJECT
public:
    explicit Encryptor(QObject *parent = 0);
    ~Encryptor();

    void setup(const QString &m, const QString &pwd);//call this function only once!

    static int randomCompare(const quint8 &, const quint8 &, const quint32 &salt, const quint64 &key);
    QByteArray decrypt(const QByteArray &);
    QByteArray encrypt(const QByteArray &);

    static const QVector<quint8> octVec;
    static const QMap<QByteArray, QVector<int> > cipherMap;
    static QMap<QByteArray, QVector<int> > generateCihperMap();

private:
    bool usingTable;
    QByteArray method;
    QByteArray password;
    QVector<quint8> encTable;
    QVector<quint8> decTable;
    int keyLen;
    int ivLen;
    bool encPtrZero;
    bool decPtrZero;

    void tableInit();
    QVector<quint8> mergeSort(const QVector<quint8> &, quint32, quint64);
    QByteArray getPasswordHash();
    void generateKeyIv();
    void randIvLengthHeader(QByteArray &);
    bool selfTest();

protected:
    QCA::Initializer *qcaInit;
    QCA::Cipher *enCipher;
    QCA::Cipher *deCipher;
    QCA::SecureArray _key;
    QCA::SecureArray _iv;
};

#endif // ENCRYPTOR_H
