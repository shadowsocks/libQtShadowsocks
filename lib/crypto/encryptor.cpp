/*
 * encryptor.cpp - the source file of Encryptor class
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

#include "encryptor.h"
#include <QDebug>
#include <QtEndian>

namespace {
const size_t AEAD_CHUNK_SIZE_LEN = 2;
const uint16_t AEAD_CHUNK_SIZE_MASK = 0x3FFF;

std::string evpBytesToKey(const QSS::Cipher::CipherInfo& cipherInfo,
                          const std::string &password)
{
    std::vector<std::string> m;
    std::string data;
    int i = 0;

    while (m.size() < cipherInfo.keyLen + cipherInfo.ivLen) {
        if (i == 0) {
            data = password;
        } else {
            data = m[i - 1] + password;
        }
        m.push_back(QSS::Cipher::md5Hash(data));
        ++i;
    }

    std::string ms;
    std::for_each(m.begin(), m.end(), [&ms](const std::string& bytes) {
        ms += bytes;
    });

    return ms.substr(0, cipherInfo.keyLen);
}

}  // anonymous namespace

namespace  QSS {
Encryptor::Encryptor(const std::string &method,
                     const std::string &password) :
    m_method(method),
    m_cipherInfo(Cipher::cipherInfoMap.at(m_method)),
    m_masterKey(evpBytesToKey(m_cipherInfo, password)),
    m_incompleteLength(0)
{
}

void Encryptor::initEncipher(std::string *header)
{
    std::string iv = Cipher::randomIv(m_method);
    std::string key;
#ifdef USE_BOTAN2
    if (m_cipherInfo.type == Cipher::CipherType::AEAD) {
        const std::string salt = Cipher::randomIv(m_cipherInfo.saltLen);
        key = Cipher::deriveAeadSubkey(m_cipherInfo.keyLen, m_masterKey, salt);
        *header = salt;
    } else {
#endif
        key = m_masterKey;
        *header = iv;
#ifdef USE_BOTAN2
    }
#endif
    m_enCipher = std::make_unique<QSS::Cipher>(m_method, std::move(key), std::move(iv), true);
}

void Encryptor::initDecipher(const char *data, size_t length, size_t *offset)
{
    std::string key, iv;
#ifdef USE_BOTAN2
    if (m_cipherInfo.type == Cipher::CipherType::AEAD) {
        iv = std::string(m_cipherInfo.ivLen, static_cast<char>(0));
        if (length < m_cipherInfo.saltLen) {
            throw std::length_error("Data chunk is too small to initialise an AEAD decipher");
        }
        key = Cipher::deriveAeadSubkey(m_cipherInfo.keyLen, m_masterKey, std::string(data, m_cipherInfo.saltLen));
        *offset = m_cipherInfo.saltLen;
    } else {
#endif
        if (length < m_cipherInfo.ivLen) {
            throw std::length_error("Data chunk is too small to initialise a stream decipher");
        }
        iv = std::string(data, m_cipherInfo.ivLen);
        key = m_masterKey;
        *offset = m_cipherInfo.ivLen;
#ifdef USE_BOTAN2
    }
#endif
    m_deCipher = std::make_unique<QSS::Cipher>(m_method, std::move(key), std::move(iv), false);
}

std::string Encryptor::encrypt(const std::string &in)
{
    return encrypt(reinterpret_cast<const uint8_t*>(in.data()), in.length());
}

std::string Encryptor::encrypt(const uint8_t *data, size_t length)
{
    if (length <= 0) {
        return std::string();
    }

    std::string header;
    if (!m_enCipher) {
        initEncipher(&header);
    }

    std::string encrypted;
#ifdef USE_BOTAN2
    if (m_cipherInfo.type == Cipher::CipherType::AEAD) {
        uint16_t inLen = length > AEAD_CHUNK_SIZE_MASK ? AEAD_CHUNK_SIZE_MASK : length;
        std::string rawLength(AEAD_CHUNK_SIZE_LEN, static_cast<char>(0));
        qToBigEndian(inLen, reinterpret_cast<uint8_t*>(&rawLength[0]));
        std::string encLength = m_enCipher->update(rawLength); // length + tag
        m_enCipher->incrementIv();
        std::string encPayload = m_enCipher->update(data, inLen); // payload + tag
        m_enCipher->incrementIv();
        encrypted = encLength + encPayload;
        if (inLen < length) {
            // Append the remaining part recursively if there is any
            encrypted += encrypt(data + inLen, length - inLen);
        }
    } else {
#endif
        encrypted = m_enCipher->update(data, length);
#ifdef USE_BOTAN2
    }
#endif
    return header + encrypted;
}

std::string Encryptor::decrypt(const std::string &data)
{
    return decrypt(reinterpret_cast<const uint8_t*>(data.data()), data.length());
}

std::string Encryptor::decrypt(const uint8_t* data, size_t length)
{
    if (length <= 0) {
        return std::string();
    }

    std::string out;
    if (!m_deCipher) {
        size_t headerLength = 0;
        initDecipher(reinterpret_cast<const char*>(data), length, &headerLength);
        data += headerLength;
        length -= headerLength;
    }

#ifdef USE_BOTAN2
    if (m_cipherInfo.type == Cipher::CipherType::AEAD) {
        // Concatenate the data with incomplete chunk (if it exists)
        std::string chunk = m_incompleteChunk + std::string(reinterpret_cast<const char*>(data), length);
        data = reinterpret_cast<const uint8_t*>(chunk.data());
        length = chunk.length();
        const uint8_t *dataEnd = data + length;

        uint16_t payloadLength = 0;
        if (m_incompleteLength != 0u) {
            // The payload length is already known
            payloadLength = m_incompleteLength;
            m_incompleteLength = 0;
            m_incompleteChunk.clear();
        } else {
            if (dataEnd - data < AEAD_CHUNK_SIZE_LEN + m_cipherInfo.tagLen) {
                qDebug("AEAD data chunk is incomplete (too small for length)");
                m_incompleteChunk = std::string(reinterpret_cast<const char*>(data), dataEnd - data);
                return std::string();
            }
            std::string decLength = m_deCipher->update(data, AEAD_CHUNK_SIZE_LEN + m_cipherInfo.tagLen);
            m_deCipher->incrementIv();
            data += (AEAD_CHUNK_SIZE_LEN + m_cipherInfo.tagLen);
            payloadLength = qFromBigEndian(*reinterpret_cast<const uint16_t*>(decLength.data())) & AEAD_CHUNK_SIZE_MASK;
            if (payloadLength == 0) {
                throw std::length_error("AEAD data chunk length is invalid");
            }
        }

        if (dataEnd - data < payloadLength + m_cipherInfo.tagLen) {
            qDebug("AEAD data chunk is incomplete (too small for payload)");
            m_incompleteChunk = std::string(reinterpret_cast<const char*>(data), dataEnd - data);
            m_incompleteLength = payloadLength;
            return std::string();
        }
        out = m_deCipher->update(data, payloadLength + m_cipherInfo.tagLen);
        m_deCipher->incrementIv();
        data += (payloadLength + m_cipherInfo.tagLen);
        if (dataEnd > data) {
            // Append remaining decrypted chunks recursively if there is any
            out += decrypt(data, dataEnd - data);
        }
    } else {
#endif
        out = m_deCipher->update(data, length);
#ifdef USE_BOTAN2
    }
#endif
    return out;
}

std::string Encryptor::encryptAll(const std::string &in)
{
    return encryptAll(reinterpret_cast<const uint8_t*>(in.data()), in.length());
}

std::string Encryptor::encryptAll(const uint8_t *data, size_t length)
{
    std::string header;
    initEncipher(&header);
    return header + m_enCipher->update(data, length);
}

std::string Encryptor::decryptAll(const std::string &data)
{
    return decryptAll(reinterpret_cast<const uint8_t*>(data.data()), data.length());
}

std::string Encryptor::decryptAll(const uint8_t* data, size_t length)
{
    size_t headerLength = 0; // IV or salt length
    initDecipher(reinterpret_cast<const char*>(data), length, &headerLength);
    data += headerLength;
    length -= headerLength;
    return m_deCipher->update(data, length);
}

} // namespace QSS
