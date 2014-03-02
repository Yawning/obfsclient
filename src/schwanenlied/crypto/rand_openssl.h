/**
 * @file    rand_openssl.h
 * @author  Yawning Angel
 * @brief   OpenSSL CSPRNG
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

#ifndef SCHWANENLIED_CRYPTO_RAND_OPENSSL_H__
#define SCHWANENLIED_CRYPTO_RAND_OPENSSL_H__

#include <openssl/rand.h>

#include "schwanenlied/common.h"

namespace schwanenlied {
namespace crypto {

/**
 * A wrapper around OpenSSL's RNG
 *
 * This allows use with the numerics library for convinience.
 */
class RandOpenSSL {
 public:
  /** The PRNG output type */
  typedef uint32_t result_type;

  /** @{ */
  /** Smallest possible value in the output range */
  static constexpr result_type min() { return 0; }
  /** Largest possible value in the output range */
  static constexpr result_type max() { return UINT32_MAX; }
  /** @} */

  /** Return the next value */
  result_type operator()() {
    result_type ret;

    if (1 != ::RAND_bytes(reinterpret_cast<unsigned char*>(&ret), sizeof(ret)))
      SL_ABORT("::RAND_bytes() failed!");

    return ret;
  }

  /**
   * Fill a buffer with random bytes
   *
   * @param[in] buf   The buffer to fill
   * @param[in] len   The length of buf
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool get_bytes(uint8_t* buf,
                 const size_t len) {
    if (1 != ::RAND_bytes(buf, len))
      return false;
    return true;
  }
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_RAND_OPENSSL_H__
