/**
 * @file    sha256.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SHA256
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

#ifndef SCHWANENLIED_CRYPTO_SHA256_H__
#define SCHWANENLIED_CRYPTO_SHA256_H__

#include "schwanenlied/common.h"

namespace schwanenlied {
namespace crypto {

/**
 * A simple wrapper around OpenSSL's SHA256 implementation
 */
class Sha256 {
 public:
  /** The digest length in bytes */
  static const size_t kDigestLength = 32;

  /** Construct a Sha256 instance */
  Sha256() {}

  ~Sha256() = default;

  /**
   * One shot digest calculation
   *
   * @param[in]   buf     A pointer to the buffer to be hashed
   * @param[in]   len     The size of the buffer to be hashed
   * @param[out]  out     A pointer to where the digest should be stored
   * @param[in]   out_len The length of the memory at out (Must be
   *                      kDigestLength)
   * @param[in]   iters   The number of iterations to calculate
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool digest(const uint8_t* buf,
              const size_t len,
              uint8_t* out,
              const size_t out_len,
              const int iters = 1) const;
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_SHA256_H__
