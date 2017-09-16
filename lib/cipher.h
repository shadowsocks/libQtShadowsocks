/*
 * cipher.h - the header file of Cipher class
 *
 * Communicate with lower-level encrytion library
 *
 * Seperated from Encryptor enables us to change low-level library easier.
 * If there is a modification associated with encryption/decryption, it's
 * this class that needs changes instead of messing up lots of classes.
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

#ifndef CIPHER_H
#define CIPHER_H

#include <array>
#include <unordered_map>
#include <memory>
#include "rc4.h"
#include "chacha.h"
#include "export.h"

namespace Botan {
class Keyed_Filter;
class Pipe;
class KDF;
}

namespace QSS {

class Cipher
{
public:
    /**
     * @brief Cipher
     * @param method The cipher method name (in Shadowsocks convention)
     * @param sKey The secret key (dervied per-session for AEAD)
     * @param iv The initialiser vector, aka nonce
     * @param encrypt Whether the operation is to encrypt, otherwise it's to decrypt
     * @param parent The parent QObject pointer
     */
    Cipher(const std::string &method, const std::string &sKey, const std::string &iv, bool encrypt);
    Cipher(Cipher &&) = default;
    ~Cipher();

    std::string update(const std::string &data);
    const std::string &getIV() const;

    enum CipherType {
        STREAM,
        AEAD
    };

    struct CipherInfo {
        std::string internalName; // internal implementation name in Botan
        int keyLen;
        int ivLen;
        CipherType type;
        int saltLen; // only for AEAD
        int tagLen; // only for AEAD
    };

    /*
     * The key of this map is the encryption method (shadowsocks convention)
     */
    static const std::unordered_map<std::string, CipherInfo> cipherInfoMap;

    /*
     * The label/info string used for key derivation function
     */
    static const std::string kdfLabel;

    static const int AUTH_LEN;

    /**
     * @brief randomIv Generates a vector of random characters of given length
     * @param length
     * @return
     */
    static std::string randomIv(int length);

    /**
     * @brief randomIv An overloaded function to generate randomised IV for given cipher method
     * For AEAD ciphers, this method returns all zeros
     * @param method The Shadowsocks cipher method name
     * @return
     */
    static std::string randomIv(const std::string& method);

    static std::string md5Hash(const std::string &in);

    /**
     * @brief isSupported
     * @param method The cipher method name in Shadowsocks convention
     * @return True if it's supported, false otherwise
     */
    static bool isSupported(const std::string &method);

    static std::vector<std::string> supportedMethods();

    /*
     * OTA is deprecated, these methods will be removed in future releases
     */
    static std::string hmacSha1(const std::string &key, const std::string &msg);

#ifdef USE_BOTAN2
    static std::string deriveAeadSubkey(size_t length, const std::string &masterKey, const std::string& salt);
#endif

private:
    Botan::Keyed_Filter *filter;
    std::unique_ptr<Botan::Pipe> pipe;
    std::unique_ptr<RC4> rc4;
    std::unique_ptr<ChaCha> chacha;
    const std::string key; // preshared key
    std::string iv; // nonce
    const CipherInfo cipherInfo;
};

}

#endif // CIPHER_H
