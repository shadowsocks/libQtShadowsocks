//Ported from chacha20_simple

#ifndef CHACHA_H
#define CHACHA_H

#include <QObject>
#include <QVector>

namespace QSS {

#define LE(p) ((static_cast<quint32>((p)[0])) | (static_cast<quint32>((p)[1]) << 8) | (static_cast<quint32>((p)[2]) << 16) | (static_cast<quint32>((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;
#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

class ChaCha : public QObject
{
    Q_OBJECT
public:
    /*
     * Key length must be 32 (16 is dropped)
     * iv is exactly the "nonce". we use IV to keep terminology consistency
     */
    explicit ChaCha(const QByteArray &_key, const QByteArray &_iv, QObject *parent = 0);

public slots:
    //encrypt (or decrypt, same process for ChaCha algorithm) a byte array.
    QByteArray update(const QByteArray &in);

private:
    QVector<quint32> schedule;//16
    QVector<quint32> keystream;//16
    quint32 available;

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
