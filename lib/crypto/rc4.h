/*
 * rc4.h - the header file of RC4 class
 *
 * Somehow, the Botan::ARC4 will cause crashes on 64-bit platforms with
 * unaligned memory. Therefore, I reimplemented RC4 here to get around
 * the crashes by not using unaligned memory xor.
 *
 * Copyright (C) 2014-2016 Symeon Huang <hzwhuang@gmail.com>
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

#include <vector>
#include <string>
#include "util/export.h"

namespace QSS {

class QSS_EXPORT RC4
{
public:
    // non-skip
    // This class implements so-called RC4-MD5 cipher instead of original RC4
    // _iv is not allowed to be empty!
    RC4(const std::string &_key,
        const std::string &_iv);

    RC4(const RC4 &) = delete;

    std::string update(const uint8_t *data, size_t length);
    std::string update(const std::string &input);

private:
    void generate();

    uint32_t position;
    unsigned char x;
    unsigned char y;
    std::vector<unsigned char> state;
    std::vector<unsigned char> buffer;
};

}

#endif // RC4_H
