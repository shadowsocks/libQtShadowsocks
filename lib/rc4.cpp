/*
 * rc4.cpp - the source file of RC4 class
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

#include "rc4.h"
#include "cipher.h"
#include "common.h"

using namespace QSS;

RC4::RC4(const QByteArray &_key, const QByteArray &_iv, QObject *parent) :
    QObject(parent),
    position(0), x(0), y(0)
{
    Q_ASSERT(!_iv.isEmpty());
    state.resize(256);
    buffer.resize(4096);//4096 is the "BOTAN_DEFAULT_BUFFER_SIZE"

    QByteArray realKey = QByteArray::fromStdString(Cipher::md5Hash(QByteArray(_key + _iv).toStdString()));
    realKey.resize(_key.size());
    unsigned char *key = reinterpret_cast<unsigned char *>(realKey.data());

    for (quint32 i = 0; i < 256; ++i) {
        state[i] = static_cast<unsigned char>(i);
    }
    for (quint32 i = 0, state_index = 0; i < 256; ++i) {
        state_index = (state_index + key[i % realKey.length()] + state[i])
                    % 256;
        std::swap(state[i], state[state_index]);
    }
    generate();
}

QByteArray RC4::update(const QByteArray &input)
{
    quint32 length = input.length();
    QByteArray output;
    output.resize(length);
    const unsigned char *in =
            reinterpret_cast<const unsigned char*>(input.constData());
    unsigned char *out =
            reinterpret_cast<unsigned char*>(output.data());

    for (quint32 delta = 4096 - position;
         length >= delta;
         delta = 4096 - position) {//4096 == buffer.size()
        Common::exclusive_or(buffer.data() + position, in, out, delta);
        length -= delta;
        in += delta;
        out += delta;
        generate();
    }
    Common::exclusive_or(buffer.data() + position, in, out, length);
    position += length;
    return output;
}

void RC4::generate()
{
    unsigned char sx, sy;
    for (int i = 0; i < buffer.size(); i += 4) {
        sx = state[x + 1]; y = (y + sx) % 256; sy = state[y];
        state[x + 1] = sy; state[y] = sx;
        buffer[i] = state[(sx + sy) % 256];

        sx = state[x + 2]; y = (y + sx) % 256; sy = state[y];
        state[x + 2] = sy; state[y] = sx;
        buffer[i + 1] = state[(sx + sy) % 256];

        sx = state[x + 3]; y = (y + sx) % 256; sy = state[y];
        state[x + 3] = sy; state[y] = sx;
        buffer[i + 2] = state[(sx + sy) % 256];

        x = (x + 4) % 256;
        sx = state[x]; y = (y + sx) % 256; sy = state[y];
        state[x] = sy; state[y] = sx;
        buffer[i + 3] = state[(sx + sy) % 256];
    }
    position = 0;
}
