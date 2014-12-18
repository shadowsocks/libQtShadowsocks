//Ported from chacha20_simple

#ifndef CHACHA_H
#define CHACHA_H

#include <QObject>
#include <QVector>

namespace QSS {

class ChaCha : public QObject
{
    Q_OBJECT
public:
    /*
     * Key length must be 32 (16 is dropped)
     * IV length must be 8
     */
    explicit ChaCha(const QByteArray &_key, const QByteArray &_iv, QObject *parent = 0);

public slots:
    //encrypt (or decrypt, same process for ChaCha algorithm) a byte array.
    QByteArray update(const QByteArray &in);

private:
    QVector<quint32> schedule;//16
    QVector<quint32> keystream;//16
    quint32 position;

    void chacha();

    inline void chacha_xor(quint8 *ks, const quint8 *in, quint8 *out, quint32 length)
    {
        quint8 *end_ks = ks + length;
        do {
            *out = *in ^ *ks;
            ++out; ++in; ++ks;
        } while (ks < end_ks);
    }
};

}

#endif // CHACHA_H
