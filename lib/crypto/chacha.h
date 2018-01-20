/*
 * chacha.h - the header file of ChaCha class
 *
 * This class is partly ported from Botan::ChaCha
 *
 * Copyright (C) 2014-2017 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef CHACHA_H
#define CHACHA_H

#include <string>
#include <vector>
#include "util/export.h"

namespace QSS {

class QSS_EXPORT ChaCha
{
public:
    /*
     * Key length must be 32 (16 is dropped)
     * IV length must be 8 or 12
     */
    ChaCha(const std::string &_key,
           const std::string &_iv);

    ChaCha(const ChaCha &) = delete;

    //encrypt (or decrypt, same process for ChaCha algorithm) a byte array.
    std::string update(const uint8_t *input, size_t length);
    std::string update(const std::string &input);

private:
    std::vector<uint32_t> m_state;
    std::vector<unsigned char> m_buffer;
    uint32_t m_position;

    void chacha();
    void setIV(const std::string &_iv);
};

}

#endif // CHACHA_H
