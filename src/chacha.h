/*
 * chacha.h - the header file of ChaCha class
 *
 * This class is partly ported from chacha20_simple and Botan::ChaCha
 *
 * Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

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
