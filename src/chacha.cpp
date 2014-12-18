#include "chacha.h"
#include <QDebug>

using namespace QSS;

ChaCha::ChaCha(const QByteArray &_key, const QByteArray &_iv, QObject *parent) :
    QObject (parent)
{
    const unsigned char *key = reinterpret_cast<const unsigned char*>(_key.constData());
    const unsigned char *iv = reinterpret_cast<const unsigned char*>(_iv.constData());
    static const QByteArray constants(32, 'k');

    schedule.resize(16);
    keystream.resize(16);

    schedule[0] = LE(constants.data() + 0);
    schedule[1] = LE(constants.data() + 4);
    schedule[2] = LE(constants.data() + 8);
    schedule[3] = LE(constants.data() + 12);
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
    available = 0;
}

QByteArray ChaCha::update(const QByteArray &in)
{
    int length = in.length();
    QByteArray out;
    out.resize(length);

    if (available > 0) {
        int amount = qMin(length, static_cast<int>(available));
        chacha_xor(reinterpret_cast<quint8 *>(keystream.data() + keystream.size() * 4 - available), reinterpret_cast<const quint8*>(in.data()), reinterpret_cast<quint8*>(out.data()), amount);
        available -= amount;
        length -= amount;
    }

    while (length > 0) {
        int amount = qMin(length, keystream.size() * 4);

        quint32 *const nonce = schedule.data() + 12;
        int i = 10;
        keystream = schedule;
        while (i--) {
            QUARTERROUND(keystream.data(), 0, 4, 8, 12)
            QUARTERROUND(keystream.data(), 1, 5, 9, 13)
            QUARTERROUND(keystream.data(), 2, 6, 10, 14)
            QUARTERROUND(keystream.data(), 3, 7, 11, 15)
            QUARTERROUND(keystream.data(), 0, 5, 10, 15)
            QUARTERROUND(keystream.data(), 1, 6, 11, 12)
            QUARTERROUND(keystream.data(), 2, 7, 8, 13)
            QUARTERROUND(keystream.data(), 3, 4, 9, 14)
        }
        for (i = 0; i < 16; ++i) {
            quint32 result = keystream[i] + schedule[i];
            FROMLE(keystream.data() + i, result);
        }
        if (!++nonce[0] && !++nonce[1] && !++nonce[2])  ++nonce[3];

        chacha_xor(reinterpret_cast<quint8 *>(keystream.data()), reinterpret_cast<const quint8*>(in.data()), reinterpret_cast<quint8*>(out.data()), amount);
        length -= amount;
        available = keystream.size() * 4 - amount;
    }

    return out;
}
