/**
 * @file    aes.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   AES Block Cipher
 *
 * @todo This probably should be in a namespace
 */

/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SCHWANENLIED_CRYPTO_AES_H__
#define SCHWANENLIED_CRYPTO_AES_H__

#include <openssl/evp.h>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/ctr.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * AES Electronic Code Book (ECB) Mode
 *
 * This provides a OpenSSL EVP interface based implementation of ECB-AES.  As
 * the only time this should be used is to provide [CTR mode](@ref crypto::Ctr),
 * the only supported operation is encrypting a block.
 */
template <const EVP_CIPHER* (F)(void), size_t kKeyLength>
class AesEcb {
 public:
  /**
   * Create a AesEcb instance
   */
  AesEcb() :
      has_key_(false) {
    ::EVP_CIPHER_CTX_init(&ctx_);
    ::EVP_CIPHER_CTX_set_padding(&ctx_, 0);
  }

  ~AesEcb() {
    ::EVP_CIPHER_CTX_cleanup(&ctx_);
  }

  /** @{ */
  /** Key length of this AesEcb instance */
  constexpr size_t key_length() const { return kKeyLength; }
  /** Block length of this AesEcb instance */
  constexpr size_t block_length() const { return kBlockLength; }
  /** @} */

  /** @} */
  /**
   * Set the key
   *
   * @param[in] key   The key (must be key_length() bytes)
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool set_key(const SecureBuffer& key) {
    if (key.size() != kKeyLength)
      return false;

    if (1 != ::EVP_EncryptInit_ex(&ctx_, F(), nullptr,
                                  key.data(), nullptr))
      return false;

    has_key_ = true;

    return true;
  }

  /**
   * Destroy the current key
   */
  void clear_key() {
    if (has_key_) {
      ::EVP_CIPHER_CTX_cleanup(&ctx_);
      has_key_ = false;
    }
  }

  /**
   * Is the key set?
   */
  const bool has_key() const { return has_key_; }
  /** @} */

  /**
   * Encrypt **one** block
   *
   * @param[in] buf   The block to encrypt
   * @param[in] len   The size of the block to encrypt (must be block_length() bytes)
   * @param[out] out  A buffer for the encrypted block
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool encrypt_block(const uint8_t* buf,
                     const size_t len,
                     uint8_t* out) {
    if (!has_key_)
      return false;
    if (len != block_length())
      return false;

    int outl = len;
    if (1 != ::EVP_EncryptUpdate(&ctx_, out, &outl, buf, len))
      return false;
    if (1 != ::EVP_EncryptFinal_ex(&ctx_, out + outl, &outl))
      return false;

    return true;
  }

 private:
  AesEcb(const AesEcb&) = delete;
  void operator=(const AesEcb&) = delete;

  static const size_t kBlockLength = 16;  /**< AES block length */

  bool has_key_;        /**< Is the key valid? */
  EVP_CIPHER_CTX ctx_;  /**< The OpenSSL EVP context */
};

const size_t kAes128KeyLength = 16; /**< AES-128 key length */
const size_t kAes192KeyLength = 24; /**< AES-192 key length */
const size_t kAes256KeyLength = 32; /**< AES-256 key length */

/** AES-128-ECB */
typedef AesEcb<::EVP_aes_128_ecb, kAes128KeyLength> Aes128Ecb;
/** AES-192-ECB */
typedef AesEcb<::EVP_aes_192_ecb, kAes192KeyLength> Aes192Ecb;
/** AES-256-ECB */
typedef AesEcb<::EVP_aes_256_ecb, kAes256KeyLength> Aes256Ecb;

/** AES-128-CTR */
typedef Ctr<Aes128Ecb> Aes128Ctr;
/** AES-192-CTR */
typedef Ctr<Aes192Ecb> Aes192Ctr;
/** AES-256-CTR */
typedef Ctr<Aes256Ecb> Aes256Ctr;

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_AES_H__
