/*
 * common.cpp - the source file of Common class
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

#include <QTextStream>
#include <QHostInfo>
#include <QtEndian>
#include <random>
#include "common.h"
#include "lz4.h"

using namespace QSS;

QTextStream Common::qOut(stdout, QIODevice::WriteOnly | QIODevice::Unbuffered);
QVector<QByteArray> Common::failedIVVector;
QVector<QHostAddress> Common::failedAddressVector;
QVector<QHostAddress> Common::bannedAddressVector;
QMutex Common::failedIVMutex;
QMutex Common::failedAddressMutex;
QMutex Common::bannedAddressMutex;
const char Common::compressionFlag = 0b01000000;

const QByteArray Common::version()
{
    return QSS_VERSION;
}

QByteArray Common::packAddress(const Address &addr)//pack a shadowsocks header
{
    QByteArray type_bin, addr_bin, port_ns;
    port_ns.resize(2);
    qToBigEndian(addr.getPort(), reinterpret_cast<uchar*>(port_ns.data()));

    int type = addr.addressType();
    type_bin.append(static_cast<char>(type));
    if (type == Address::ADDRTYPE_HOST) {//should we care if it exceeds 255?
        QByteArray address_str = addr.getAddress().toLocal8Bit();
        addr_bin.append(static_cast<char>(address_str.length()));
        addr_bin += address_str;
    } else if (type == Address::ADDRTYPE_IPV4) {
        quint32 ipv4_addr = qToBigEndian(addr.getFirstIP().toIPv4Address());
        addr_bin = QByteArray(reinterpret_cast<char*>(&ipv4_addr), 4);
    } else {
        Q_IPV6ADDR ipv6_addr = addr.getFirstIP().toIPv6Address();//Q_IPV6ADDR is a 16-unsigned-char struct (big endian)
        addr_bin = QByteArray(reinterpret_cast<char*>(ipv6_addr.c), 16);
    }

    return type_bin + addr_bin + port_ns;
}

QByteArray Common::packAddress(const QHostAddress &addr, const quint16 &port)
{
    QByteArray type_bin, addr_bin, port_ns;
    port_ns.resize(2);
    qToBigEndian(port, reinterpret_cast<uchar*>(port_ns.data()));
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        quint32 ipv4_addr = qToBigEndian(addr.toIPv4Address());
        type_bin.append(static_cast<char>(Address::ADDRTYPE_IPV4));
        addr_bin = QByteArray(reinterpret_cast<char*>(&ipv4_addr), 4);
    } else {
        type_bin.append(static_cast<char>(Address::ADDRTYPE_IPV6));
        Q_IPV6ADDR ipv6_addr = addr.toIPv6Address();
        addr_bin = QByteArray(reinterpret_cast<char*>(ipv6_addr.c), 16);
    }
    return type_bin + addr_bin + port_ns;
}

void Common::parseHeader(const QByteArray &data, Address &dest, int &header_length)
{
    int addrtype = static_cast<int>(data[0]);
    header_length = 0;

    if (addrtype == Address::ADDRTYPE_HOST) {
        if (data.length() > 2) {
            int addrlen = static_cast<int>(data[1]);
            if (data.size() >= 2 + addrlen) {
                dest.setPort(qFromBigEndian(*reinterpret_cast<const quint16 *>(data.data() + 2 + addrlen)));
                dest.setAddress(QString(data.mid(2, addrlen)));
                header_length = 4 + addrlen;
            }
        }
    } else if (addrtype == Address::ADDRTYPE_IPV4) {
        if (data.length() >= 7) {
            QHostAddress addr(qFromBigEndian(*reinterpret_cast<const quint32 *>(data.data() + 1)));
            if (!addr.isNull()) {
                header_length = 7;
                dest.setIPAddress(addr);
                dest.setPort(qFromBigEndian(*reinterpret_cast<const quint16 *>(data.data() + 5)));
            }
        }
    } else if (addrtype == Address::ADDRTYPE_IPV6) {
        if (data.length() >= 19) {
            Q_IPV6ADDR ipv6_addr;
            memcpy(ipv6_addr.c, data.data() + 1, 16);
            QHostAddress addr(ipv6_addr);
            if (!addr.isNull()) {
                header_length = 19;
                dest.setIPAddress(addr);
                dest.setPort(qFromBigEndian(*reinterpret_cast<const quint16 *>(data.data() + 17)));
            }
        }
    } else {
        qWarning("Unknown ATYP %d", addrtype);
    }
}

void Common::parseHeader(QByteArray &data, Address &dest, int &header_length, bool &compression)
{
    char atyp = data[0];
    compression |= (atyp & compressionFlag);
    data[0] = (static_cast<char>(atyp << 4) >> 4);
    parseHeader(data, dest, header_length);
}

int Common::randomNumber(int max, int min)
{
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int> dis(min, max - 1);
    return dis(engine);
}

void Common::exclusive_or(unsigned char *ks, const unsigned char *in, unsigned char *out, quint32 length)
{
    unsigned char *end_ks = ks + length;
    do {
        *out = *in ^ *ks;
        ++out; ++in; ++ks;
    } while (ks < end_ks);
}

QByteArray Common::lz4Compress(const QByteArray &src)
{
    QByteArray dest;
    dest.resize(LZ4_compressBound(src.size()));
    int real_size = LZ4_compress_default(src.constData(), dest.data(), src.size(), dest.size());
    if (real_size == 0) {
        return QByteArray();
    } else {
        dest.resize(real_size);
        QByteArray sizeInfo(8, 0);//full dest size | decompressed size
        qToBigEndian(dest.size() + 8, reinterpret_cast<uchar*>(sizeInfo.data()));
        qToBigEndian(src.size(), reinterpret_cast<uchar*>(sizeInfo.data() + 4));
        dest.prepend(sizeInfo);
        return dest;
        /*
         * structure of compressed shadowsocks data
         * +------------+-------------+----------------+
         * | CHUNK SIZE | SOURCE SIZE | LZ4 COMPRESSED |
         * +------------+-------------+----------------+
         * |     4      |      4      |     Variable   |
         * +------------+-------------+----------------+
         */
    }
}

QByteArray Common::lz4Decompress(const QByteArray &src, QByteArray &incompleteChunk)
{
    QByteArray out;
    const char *srcPtr;
    int chunk_size, source_size;
    for (int pos = 0; pos < src.size(); pos += chunk_size) {
        srcPtr = src.constData() + pos;
        chunk_size = qFromBigEndian(*reinterpret_cast<const int*>(srcPtr));
        source_size = qFromBigEndian(*reinterpret_cast<const int*>(srcPtr + 4));

        if (chunk_size > src.size() - pos) {
            incompleteChunk = src.mid(pos);
            break;
        }

        QByteArray dest;
        dest.resize(source_size);
        int real_size = LZ4_decompress_safe(srcPtr + 8, dest.data(), chunk_size - 8, source_size);
        if (real_size <= 0) {
            return QByteArray();
        }
        dest.resize(real_size);
        out.append(dest);
    }
    return out;
}
