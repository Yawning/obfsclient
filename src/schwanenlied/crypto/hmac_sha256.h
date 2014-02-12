/**
 * @file    hmac_sha256.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   HMAC-SHA256
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

#ifndef SCHWANENLIED_CRYPTO_HMAC_SHA256_H__
#define SCHWANENLIED_CRYPTO_HMAC_SHA256_H__

#include <openssl/hmac.h>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * A simple wrapper around OpenSSL's HMAC-SHA256 implementation
 */
class HmacSha256 {
 public:
  /** The digest length in bytes */
  static const size_t kDigestLength = 32;

  /**
   * Construct a HmacSha256 instance
   *
   * set_key() must be called before digests can be obtained.
   */
  HmacSha256() :
      has_key_(false) {
    ::HMAC_CTX_init(&ctx_);
  }

  /**
   * Construct a HmacSha256 instance
   *
   * @param[in] key   The key to use when calculating digests
   */
  HmacSha256(const SecureBuffer& key) :
      has_key_(true),
      key_(key) {
    ::HMAC_CTX_init(&ctx_);
  }

  ~HmacSha256() {
    ::HMAC_CTX_cleanup(&ctx_);
  }

  /** @{ */
  /**
   * Set the key
   *
   * @warning This will invalidate digest calculations in progress via the
   * streaming interface
   *
   * @param[in] key   The key to use when calculating digests
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool set_key(const SecureBuffer& key);
  /** @} */

  /** @{ */
  /**
   * Initialize the streaming interface
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool init();

  /**
   * HMAC additional data via the streaming interface
   *
   * @param[in] buf   A pointer to the buffer to be HMACed
   * @param[in] len   The size of the buffer to HMAC
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool update(const uint8_t* buf,
              const size_t len);

  /**
   * Obtain the digest from the streaming interface
   *
   * @param[out] out    A pointer to where the digest should be stored
   * @param[in] out_len The length of the buffer where the digest will be stored
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool final(uint8_t* out,
             const size_t out_len);
  /** @} */

  /** @{ */
  /**
   * One shot digest calculation
   *
   * @param[in]   buf     A pointer to the buffer to be HMACed
   * @param[in]   len     The size of the buffer to be HMACed
   * @param[out]  out     A pointer to where the digest should be stored
   * @param[in]   out_len The length of the memory at out (Must be <=
   *                      kDigestLength)
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool digest(const uint8_t* buf,
              const size_t len,
              uint8_t* out,
              const size_t out_len) const;
  /** @} */

 private:
  HmacSha256(const HmacSha256&) = delete;
  void operator=(const HmacSha256&) = delete;

  /** The streaming interface state */
  enum class State {
    kINVALID, /**< init() has not been called */
    kINIT,    /**< init() has been called */
    kUPDATE,  /**< update() has been called */
    kFINAL,   /**< final() has been called */
  } stream_state_;    /**< The streaming interface state */

  bool has_key_;      /**< The key is valid? */
  SecureBuffer key_;  /**< The key used when calculating digests */
  HMAC_CTX ctx_;
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_HMAC_SHA256_H__
