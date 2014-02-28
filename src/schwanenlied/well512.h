/**
 * @file    well512.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   WELL512 PRNG
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

#ifndef SCHWANENLIED_WELL512_H__
#define SCHWANENLIED_WELL512_H__

#include <array>

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/hkdf_sha256.h"
#include "schwanenlied/crypto/rand_openssl.h"

namespace schwanenlied {

/**
 * Well Equidistributed Long-period Linear
 *
 * This implements the WELL512 PRNG by Matsumonto, L'Ecuyer, and Panneton.  It
 * provides 32 bit integers with a period of 2^512, with an interface that is
 * suitable for use with the C++ standard library numeric distributions.
 *
 * The actual algorithm implementation is from
 * [Random Number Generation](http://lomont.org/Math/Papers/2008/Lomont_PRNG_2008.pdf)
 * by Chris Lomont.
 *
 * Per the original author:
 * > Here is WELL512 C/C++ code written by the author and placed in the public
 * > domain. It is about 40% faster than the code presented on L’Ecuyer’s site,
 * > and is about 40% faster than MT19937 presented on Matsumoto’s site.
 *
 * While this variant of WELL has a massively shorter period than MT19937, the
 * quality of the output of WELL is higher, and the amount of internal state is
 * dramatically smaller.
 *
 * @warning If this is used for any sort of cryptographic purpose, you will be
 * laughed at.
 */
class Well512 {
 public:
  /** The PRNG output type */
  typedef uint32_t result_type;

  /** Construct a new Well512 instance with a random seed */
  Well512() :
      index_(0),
      state_() {
    seed(nullptr, 0);
  }

  /**
   * Construct a new Well512 instance with a specific seed
   *
   * The provided seed is extracted/expanded via HKDF-SHA256.
   *
   * @param[in] buf   The seed to use
   * @param[in] len   The length of the seed
   */
  Well512(const uint8_t* buf,
          const size_t len) :
      index_(0),
      state_() {
    seed(buf, len);
  }

  ~Well512() = default;

  /** @{ */
  /** Smallest possible value in the output range */
  static constexpr result_type min() { return 0; }
  /** Largest possible value in the output range */
  static constexpr result_type max() { return UINT32_MAX; }
  /** @} */

  /**
   * Seed the existing Well512 instance
   *
   * The provided seed is extracted/expanded via HKDF-SHA256.  If the provided
   * seed is empty, the internal state is randomized from OpenSSL's random
   * number generator.
   *
   * @param[in] buf   The seed to use
   * @param[in] len   The length of the seed
   */
  void seed(const uint8_t* buf,
            const size_t len) {
    if (buf == nullptr || len == 0) {
      crypto::RandOpenSSL rand;
      if (!rand.get_bytes(reinterpret_cast<uint8_t*>(state_.data()),
                          kStateSize))
        SL_ABORT("Failed to seed from OpenSSL");
    } else {
      const auto ikm = crypto::SecureBuffer(buf, len);
      const auto prk = crypto::HkdfSha256::extract(nullptr, 0, ikm);
      const auto okm = crypto::HkdfSha256::expand(prk, nullptr, 0, kStateSize);
      ::std::memcpy(state_.data(), okm.data(), okm.size());
    }
    index_ = 0;
  }

  /** Return the next value */
  result_type operator()() {
    uint32_t a = state_[index_];
    uint32_t c = state_[(index_ + 13) & 15];
    uint32_t b = a^ c^ (a << 16) ^ (c << 15);
    c = state_[(index_ + 9) & 15];
    c ^= (c >> 11);
    a = state_[index_] = b ^ c;
    uint32_t d = a ^ ((a << 5) & 0xda442d24UL);
    index_ = (index_ + 15) & 15;
    a = state_[index_];
    state_[index_] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28);
    return state_[index_];
  }

 private:
  Well512(const Well512&) = delete;
  void operator=(const Well512&) = delete;

  /** The internal state size in bytes */
  static constexpr size_t kStateSize = sizeof(uint32_t) * 16;

  size_t index_;                        /**< Index into state_ */
  ::std::array<result_type, 16> state_; /**< The PRNG state */
};

} // namespace schwanenlied

#endif // SCHWANENLIED_WELL512_H__
