/*
 * rc4.h - the header file of RC4 class
 *
 * Somehow, the Botan::ARC4 will cause crashes on 64-bit platforms with
 * unaligned memory. Therefore, I reimplemented RC4 here to get around
 * the crashes by not using unaligned memory xor.
 *
 * Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libQtShadowsocks; see the file LICENSE. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef RC4_H
#define RC4_H

#include <QObject>
#include <QVector>

namespace QSS {

class RC4 : public QObject
{
    Q_OBJECT
public:
    //non-skip
    explicit RC4(const QByteArray &_key, const QByteArray &_iv, QObject *parent = 0);

public slots:
    QByteArray update(const QByteArray &input);

private:
    void generate();

    quint32 position;
    unsigned char x, y;
    QVector<unsigned char> state;
    QVector<unsigned char> buffer;
};

}

#endif // RC4_H
