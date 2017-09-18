/*
 * cipher.cpp - the source file of Cipher class
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

#include "cipher.h"

#include <botan/auto_rng.h>
#include <botan/key_filt.h>
#include <botan/lookup.h>
#include <botan/pipe.h>
#include <botan/md5.h>

#ifdef USE_BOTAN2
#include <botan/hkdf.h>
#include <botan/hmac.h>
#include <botan/sha160.h>
#endif

#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <stdexcept>
#include <memory>

using namespace QSS;

#ifdef USE_BOTAN2
typedef Botan::secure_vector<Botan::byte> SecureByteArray;
#define DataOfSecureByteArray(sba) sba.data()
#else
typedef Botan::SecureVector<Botan::byte> SecureByteArray;
#define DataOfSecureByteArray(sba) sba.begin()
#endif

namespace {

// Copied from libsodium's sodium_increment
void nonceIncrement(unsigned char *n, const size_t nlen)
{
    uint_fast16_t c = 1U;
    for (size_t i = 0U; i < nlen; i++) {
        c += static_cast<uint_fast16_t>(n[i]);
        n[i] = static_cast<unsigned char>(c);
        c >>= 8;
    }
}

}

Cipher::Cipher(const std::string &method,
               const std::string &sKey,
               const std::string &iv,
               bool encrypt) :
    key(sKey),
    iv(iv),
    cipherInfo(cipherInfoMap.at(method))
{
    if (method.find("rc4") != std::string::npos) {
        rc4.reset(new RC4(key, iv));
        return;
    }
#ifndef USE_BOTAN2
    else if (method.find("chacha20") != std::string::npos) {
        chacha.reset(new ChaCha(key, iv));
        return;
    }
#endif
    try {
        Botan::SymmetricKey _key(
                    reinterpret_cast<const Botan::byte *>(key.data()),
                    key.size());
        Botan::InitializationVector _iv(
                    reinterpret_cast<const Botan::byte *>(iv.data()),
                    iv.size());
        filter = Botan::get_cipher(cipherInfo.internalName, _key, _iv,
                    encrypt ? Botan::ENCRYPTION : Botan::DECRYPTION);
        // Botan::pipe will take control over filter
        // we shouldn't deallocate filter externally
        pipe.reset(new Botan::Pipe(filter));
    } catch(const Botan::Exception &e) {
        qFatal("%s\n", e.what());
    }
}

Cipher::~Cipher()
{
}

const std::unordered_map<std::string, Cipher::CipherInfo> Cipher::cipherInfoMap = {
    {"aes-128-cfb", {"AES-128/CFB", 16, 16, Cipher::CipherType::STREAM}},
    {"aes-192-cfb", {"AES-192/CFB", 24, 16, Cipher::CipherType::STREAM}},
    {"aes-256-cfb", {"AES-256/CFB", 32, 16, Cipher::CipherType::STREAM}},
    {"aes-128-ctr", {"AES-128/CTR-BE", 16, 16, Cipher::CipherType::STREAM}},
    {"aes-192-ctr", {"AES-192/CTR-BE", 24, 16, Cipher::CipherType::STREAM}},
    {"aes-256-ctr", {"AES-256/CTR-BE", 32, 16, Cipher::CipherType::STREAM}},
    {"bf-cfb", {"Blowfish/CFB", 16, 8, Cipher::CipherType::STREAM}},
    {"camellia-128-cfb", {"Camellia-128/CFB", 16, 16, Cipher::CipherType::STREAM}},
    {"camellia-192-cfb", {"Camellia-192/CFB", 24, 16, Cipher::CipherType::STREAM}},
    {"camellia-256-cfb", {"Camellia-256/CFB", 32, 16, Cipher::CipherType::STREAM}},
    {"cast5-cfb", {"CAST-128/CFB", 16, 8, Cipher::CipherType::STREAM}},
    {"chacha20", {"ChaCha", 32, 8, Cipher::CipherType::STREAM}},
    {"chacha20-ietf", {"ChaCha", 32, 12, Cipher::CipherType::STREAM}},
    {"des-cfb", {"DES/CFB", 8, 8, Cipher::CipherType::STREAM}},
    {"idea-cfb", {"IDEA/CFB", 16, 8, Cipher::CipherType::STREAM}},
    {"rc2-cfb", {"RC2/CFB", 16, 8, Cipher::CipherType::STREAM}},
    {"rc4-md5", {"RC4-MD5", 16, 16, Cipher::CipherType::STREAM}},
    {"salsa20", {"Salsa20", 32, 8, Cipher::CipherType::STREAM}},
    {"seed-cfb", {"SEED/CFB", 16, 16, Cipher::CipherType::STREAM}},
    {"serpent-256-cfb", {"Serpent/CFB", 32, 16, Cipher::CipherType::STREAM}}
#ifdef USE_BOTAN2
   ,{"aes-128-gcm", {"AES-128/GCM", 16, 12, Cipher::CipherType::AEAD, 16, 16}},
    {"aes-192-gcm", {"AES-192/GCM", 24, 12, Cipher::CipherType::AEAD, 24, 16}},
    {"aes-256-gcm", {"AES-256/GCM", 32, 12, Cipher::CipherType::AEAD, 32, 16}}
#endif
};
const std::string Cipher::kdfLabel = {"ss-subkey"};

std::string Cipher::update(const std::string &data)
{
    return update(reinterpret_cast<const uint8_t*>(data.data()), data.length());
}

std::string Cipher::update(const uint8_t *data, size_t length)
{
    if (chacha) {
        return chacha->update(data, length);
    } else if (rc4) {
        return rc4->update(data, length);
    } else if (pipe) {
        pipe->process_msg(reinterpret_cast<const Botan::byte *>
                          (data), length);
        SecureByteArray c = pipe->read_all(Botan::Pipe::LAST_MESSAGE);
        return std::string(reinterpret_cast<const char *>(DataOfSecureByteArray(c)),
                           c.size());
    } else {
        throw std::logic_error("Underlying ciphers are all uninitialised!");
    }
}

void Cipher::incrementIv()
{
    nonceIncrement(reinterpret_cast<unsigned char*>(&iv[0]), iv.length());
    filter->set_iv(Botan::InitializationVector(
                       reinterpret_cast<const Botan::byte *>(iv.data()), iv.size()
                       ));
}

std::string Cipher::randomIv(int length)
{
    //directly return empty byte array if no need to genenrate iv
    if (length == 0) {
        return std::string();
    }

    Botan::AutoSeeded_RNG rng;
    SecureByteArray out = rng.random_vec(length);
    return std::string(reinterpret_cast<const char *>(DataOfSecureByteArray(out)), out.size());
}

std::string Cipher::randomIv(const std::string &method)
{
    CipherInfo cipherInfo = cipherInfoMap.at(method);
    if (cipherInfo.type == AEAD) {
        return std::string(cipherInfo.ivLen, static_cast<char>(0));
    } else {
        return randomIv(cipherInfo.ivLen);
    }
}

std::string Cipher::md5Hash(const std::string &in)
{
    Botan::MD5 md5;
    SecureByteArray result = md5.process(in);
    return std::string(reinterpret_cast<const char*>(DataOfSecureByteArray(result)), result.size());
}

bool Cipher::isSupported(const std::string &method)
{
#ifndef USE_BOTAN2
    if (method.find("chacha20") != std::string::npos)  return true;
#endif

    if (method.find("rc4") == std::string::npos) {
        std::unique_ptr<Botan::Keyed_Filter> filter;
        try {
            filter.reset(Botan::get_cipher(method, Botan::ENCRYPTION));
        } catch (Botan::Exception &e) {
            qDebug("%s\n", e.what());
            return false;
        }
    }
    return true;
}

std::vector<std::string> Cipher::supportedMethods()
{
    std::vector<std::string> supportedMethods;
    for (auto& cipher : Cipher::cipherInfoMap) {
        if (Cipher::isSupported(cipher.second.internalName)) {
            supportedMethods.push_back(cipher.first);
        }
    }
    return supportedMethods;
}

#ifdef USE_BOTAN2
/*
 * Derives per-session subkey from the master key, which is required
 * for Shadowsocks AEAD ciphers
 */
std::string Cipher::deriveAeadSubkey(size_t length, const std::string& masterKey, const std::string& salt)
{
    std::unique_ptr<Botan::KDF> kdf;
    kdf.reset(new Botan::HKDF(new Botan::HMAC(new Botan::SHA_160())));
    //std::string salt = randomIv(cipherInfo.saltLen);
    SecureByteArray skey = kdf->derive_key(length, reinterpret_cast<const uint8_t*>(masterKey.data()), masterKey.length(), salt, kdfLabel);
    return std::string(reinterpret_cast<const char *>(DataOfSecureByteArray(skey)),
                       skey.size());
}
#endif
