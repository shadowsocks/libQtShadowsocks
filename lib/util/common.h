/*
 * common.h - includes commonly used classes or datatype
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

#ifndef COMMON_H
#define COMMON_H

#include <QHostAddress>
#include "export.h"

namespace QSS {

class Address;

namespace Common {

QSS_EXPORT const char* version();
QSS_EXPORT std::string packAddress(const Address &addr);
//this will never use ADDRTYPE_HOST because addr is an IP address
QSS_EXPORT std::string packAddress(const QHostAddress &addr,
                                   const uint16_t &port);
QSS_EXPORT void parseHeader(const std::string &data,
                            Address &addr,
                            int &length);
//generate a random number which is in the range [min, max)
QSS_EXPORT int randomNumber(int max, int min = 0);
QSS_EXPORT void exclusive_or(unsigned char *ks,
                             const unsigned char *in,
                             unsigned char *out,
                             uint32_t length);
QSS_EXPORT void banAddress(const QHostAddress &addr);
QSS_EXPORT bool isAddressBanned(const QHostAddress &addr);

QSS_EXPORT std::string stringFromHex(const std::string&);

extern const uint8_t ADDRESS_MASK;
}

}

#endif // COMMON_H
