/**
 * @file    aes_ctr128.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   AES-CTR-128
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

#ifndef SCHWANENLIED_CRYPTO_AES_CTR128_H__
#define SCHWANENLIED_CRYPTO_AES_CTR128_H__

#include <openssl/aes.h>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * OpenSSL based AES-CTR-128
 *
 * Apparently assuming that OpenSSL implements AES-CTR is a mistake, so this
 * provides AES-CTR assuming that AES-ECB is available.
 *
 * @bug This should use the EVP interface and EVP_aes_128_ctr(), assuming that
 * said interface lets us actually use a 128 bit counter.
 */
class AesCtr128 {
 public:
  /** The key length in bytes */
  static const size_t kKeyLength = 16;
  /** The max counter length in bytes */
  static const size_t kMaxCtrLength = 16;

  /**
   * Create a new AES-CTR-128 instance
   */
  AesCtr128() :
      has_state_(false),
      ctr_(kMaxCtrLength, 0),
      block_(kBlockLength, 0),
      offset_(0) {}

  ~AesCtr128();

  /**
   * Initialize the key and counter
   *
   * @param[in] key     The key to use (must be kKeyLength long)
   * @param[in] ctr     A pointer to the initial counter
   * @param[in] ctr_len The length of the initial counter
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool set_state(const SecureBuffer& key,
                 const uint8_t* ctr,
                 const size_t ctr_len);

  /**
   * Destroy the current state
   */
  void clear_state();

  /**
   * Is the key and counter initialized?
   */
  const bool has_state() const { return has_state_; }

  /**
   * Encrypt/Decrypt data
   *
   * As AES-CTR-128 does the exact same thing when encrypting and decrypting
   * only one routine is provided to handle both.
   *
   * @param[in]   buf The data to encrypt/decrypt
   * @param[in]   len The size of the data to encrypt/decrypt
   * @param[out]  out A buffer for the processed data
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool process(const uint8_t* buf,
               const size_t len,
               uint8_t* out);

 private:
  AesCtr128(const AesCtr128&) = delete;
  void operator=(const AesCtr128&) = delete;

  /** The AES block size in bytes */
  static const size_t kBlockLength = 16;

  bool has_state_;      /**< Is the internal state initialized */
  SecureBuffer ctr_;    /**< The counter */
  SecureBuffer block_;  /**< The ECB encrypted counter */
  size_t offset_;       /**< The offset into the counter */

  AES_KEY key_;         /**< The OpenSSL AES key */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_AES_CTR128_H__
