/**
 * @file    rand_ctr_drbg.h
 * @author  Yawning Angel
 * @brief   CTR-DRBG-AES
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

#ifndef SCHWANENLIED_CRYPTO_RAND_CTR_DRBG_H__
#define SCHWANENLIED_CRYPTO_RAND_CTR_DRBG_H__

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/aes.h"
#include "schwanenlied/crypto/hkdf_sha256.h"
#include "schwanenlied/crypto/rand_openssl.h"

namespace schwanenlied {
namespace crypto {

/**
 * A NIST SP 800-90A style CTR_DRBG, using CTR-AES-128
 *
 * To all the paranoid people, no this is NOT the Dual_EC_DRBG, and some of the
 * features are omitted for implementation simplicity (personalization_string)
 * is hardcoded to be null.
 *
 * This allows use with the numerics library for convinience.
 */
class RandCtrDrbg {
 public:
  /** The PRNG output type */
  typedef uint32_t result_type;

  /* Construct a new RandCtrDrbg instance with a random seed */
  RandCtrDrbg() {
    seed();
  }

  /**
   * Construct a new RandCtrDrbg instance with a specific seed
   *
   * The provided seed is extracted/expanded via HKDF-SHA256
   *
   * @param[in] buf   The seed to use
   * @param[in] len   The length of the seed
   */
  RandCtrDrbg(const uint8_t* buf,
              const size_t len) {
    seed(buf, len);
  }

  ~RandCtrDrbg() = default;

  /** @{ */
  /** Smallest possible value in the output range */
  static constexpr result_type min() { return 0; }
  /** Largest possible value in the output range */
  static constexpr result_type max() { return UINT32_MAX; }
  /** Seed length (seedlen) in bytes */
  static constexpr size_t seed_len() { return 256 / 8; }
  /** @} */

  /** Return the next value */
  result_type operator()() {
    if (request_ctr_++ > kReseedInterval)
      seed();

    result_type ret = 0;

    if (!get_bytes(reinterpret_cast<unsigned char*>(&ret), sizeof(ret)))
      SL_ABORT("get_bytes() failed!");

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
    if (len > kMaxRequestSize)
      return false;
    if (request_ctr_++ > kReseedInterval)
      seed();
    memwipe(buf, len);
    return ctr_.process(buf, len, buf);
  }

  /**
   * Seed the existing RandCtrDrbg instance
   *
   * The provided seed is extracted/expanded via HKDF-SHA256.  If the provided
   * seed is empty, the internal state is set directly from OpenSSL's random
   * number generator
   *
   * @param[in] buf   The seed to use
   * @param[in] len   The length of the seed
   */
  void seed(const uint8_t* buf = nullptr,
            const size_t len = 0) {
    SecureBuffer key(kAes128KeyLength, 0);
    SecureBuffer ctr(16, 0);

    if (buf == nullptr || len == 0) {
      RandOpenSSL rand;
      if (!rand.get_bytes(&key[0], key.size()))
        SL_ABORT("Failed to obtain a random AES key");
      if (!rand.get_bytes(&ctr[0], ctr.size()))
        SL_ABORT("Failed to obtain a random CTR");
    } else {
      const auto ikm = crypto::SecureBuffer(buf, len);
      const auto prk = crypto::HkdfSha256::extract(nullptr, 0, ikm);
      const auto okm = crypto::HkdfSha256::expand(prk, nullptr, 0, seed_len());
      SL_ASSERT(key.size() + ctr.size() == okm.size());
      key.assign(okm.data(), key.size());
      ctr.assign(okm.data() + key.size(), ctr.size());
    }

    if (!ctr_.set_state(key, nullptr, 0, ctr.data(), ctr.size()))
      SL_ABORT("Failed to set the CTR state");
    request_ctr_ = 0;
  }

 private:
  RandCtrDrbg(const RandCtrDrbg&) = delete;
  void operator=(RandCtrDrbg&) = delete;

  /** Number of requests between reseeds (reseed_interval) */
  static constexpr uint64_t kReseedInterval = 0x1000000000000ULL;
  /** Max number of bytes per request  (2 ^ 19 bits) */
  static constexpr size_t kMaxRequestSize = 0x10000;

  Aes128Ctr ctr_;         /**< CTR-AES-128 instance */
  uint64_t request_ctr_;  /**< Number of requests since last seed */
};

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_RAND_CTR_DRBG_H__
