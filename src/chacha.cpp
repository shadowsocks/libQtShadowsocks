#include "chacha.h"
#include <QDebug>

using namespace QSS;

#define LE(p) ((static_cast<quint32>((p)[0])) | (static_cast<quint32>((p)[1]) << 8) | (static_cast<quint32>((p)[2]) << 16) | (static_cast<quint32>((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;
#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

ChaCha::ChaCha(const QByteArray &_key, const QByteArray &_iv, QObject *parent) :
    QObject (parent)
{
    const quint8 *key = reinterpret_cast<const quint8*>(_key.constData());
    const quint8 *iv = reinterpret_cast<const quint8*>(_iv.constData());

    schedule.resize(16);
    keystream.resize(16);

    schedule[0] = 0x61707865;
    schedule[1] = 0x3320646e;
    schedule[2] = 0x79622d32;
    schedule[3] = 0x6b206574;
    schedule[4] = LE(key + 0);
    schedule[5] = LE(key + 4);
    schedule[6] = LE(key + 8);
    schedule[7] = LE(key + 12);
    schedule[8] = LE(key + 16);
    schedule[9] = LE(key + 20);
    schedule[10] = LE(key + 24);
    schedule[11] = LE(key + 28);
    schedule[12] = 0;
    schedule[13] = 0;
    schedule[14] = LE(iv + 0);
    schedule[15] = LE(iv + 4);
    chacha();
    position = 0;
}

void ChaCha::chacha()
{
    keystream = schedule;
    for (int i = 0; i < 10; ++i) {
        QUARTERROUND(keystream.data(), 0, 4, 8, 12)
        QUARTERROUND(keystream.data(), 1, 5, 9, 13)
        QUARTERROUND(keystream.data(), 2, 6, 10, 14)
        QUARTERROUND(keystream.data(), 3, 7, 11, 15)
        QUARTERROUND(keystream.data(), 0, 5, 10, 15)
        QUARTERROUND(keystream.data(), 1, 6, 11, 12)
        QUARTERROUND(keystream.data(), 2, 7, 8, 13)
        QUARTERROUND(keystream.data(), 3, 4, 9, 14)
    }
    for (int i = 0; i < 16; ++i) {
        quint32 result = keystream[i] + schedule[i];
        FROMLE(keystream.data() + i, result);
    }
    ++schedule[12];
    schedule[13] += (schedule[12] == 0);
}

QByteArray ChaCha::update(const QByteArray &in)
{
    quint32 length = in.length();
    QByteArray out;
    out.resize(length);
    const quint8 *inpointer = reinterpret_cast<const quint8*>(in.data());
    quint8 *outpointer = reinterpret_cast<quint8*>(out.data());

    for (quint32 delta = 64 - position; length >= delta; delta = 64 - position) {//keystream.size() * 4 = 64
        chacha_xor(reinterpret_cast<quint8 *>(keystream.data()) + position, inpointer, outpointer, delta);
        length -= delta;
        inpointer += delta;
        outpointer += delta;
        chacha();
        position = 0;
    }

    chacha_xor(reinterpret_cast<quint8 *>(keystream.data()) + position, inpointer, outpointer, length);
    position += length;
    return out;
}
