#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <QObject>
#include <QVector>
#include <QMap>
#include <QCryptographicHash>
#include <qca.h>

class Encryptor : public QObject
{
    Q_OBJECT
public:
    explicit Encryptor(QObject *parent = 0);
    ~Encryptor();

    void setup();

    static int randomCompare(const quint8 &, const quint8 &, const quint32 &salt, const quint64 &key);
    QByteArray decrypt(const QByteArray &);
    QByteArray encrypt(const QByteArray &);

    static const QVector<quint8> octVec;
    static const QMap<QByteArray, QVector<int> > cipherMap;
    static QMap<QByteArray, QVector<int> > generateCihperMap();
    static void initialise(const QString &m, const QString &pwd);

private:
    static bool usingTable;
    static QString cipherMode;
    static QByteArray method;
    static QByteArray password;
    static QVector<quint8> encTable;
    static QVector<quint8> decTable;
    static int keyLen;
    static int ivLen;
    bool ivSent;

    static void tableInit();
    static QVector<quint8> mergeSort(const QVector<quint8> &, quint32, quint64);
    void evpBytesToKey();
    static void randIvLengthHeader(QByteArray &);
    static QByteArray randomIv();
    bool selfTest();

protected:
    QCA::Cipher *enCipher;
    QCA::Cipher *deCipher;
    static QCA::SymmetricKey _key;
    QCA::SecureArray _iv;//this is used for encrypt cipher
};

#endif // ENCRYPTOR_H
