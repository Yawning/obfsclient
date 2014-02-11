/**
 * @file    hkdf_sha256.h
 * @author  Yawning Angel
 * @brief   HKDF-SHA256
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

#ifndef SCHWANENLIED_CRYPTO_HKDF_SHA256_H__
#define SCHWANENLIED_CRYPTO_HKDF_SHA256_H__

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/hmac_sha256.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace crypto {

/**
 * HMAC-Based Extract-and-Expand Key Derivation Function (SHA-256)
 *
 * This is a straight forward implementation of
 * [HKDF](http://tools.ietf.org/html/rfc5869) with HMAC-SHA-256 as the hash
 * algorithm.
 */
namespace HkdfSha256 {

/**
 * HKDF-Extract (SHA-256)
 *
 *     Let H(t, x) be HMAC-SHA-256 with key t, and message x.
 *
 *     HKDF-Extract(salt, IKM) -> PRK
 *
 *         PRK = H(salt, IKM)
 *
 * @param[in] salt      A pointer to the salt
 * @param[in] salt_len  The size of the salt
 * @param[in] ikm       The initial keying material to extract
 *
 * @returns The extracted key material
 */
SecureBuffer extract(const uint8_t* salt,
                     const size_t salt_len,
                     const SecureBuffer& ikm);

/**
 * HKDF-Expand (SHA-256)
 *
 *     Let H(t, x) be HMAC-SHA-256 with key t, and message x.
 *
 *     HKDF-Expand(PRK, info, L) -> OKM
 *
 *         N = ceil(L/HashLen)
 *
 *         T = T(1) | T(2) | T(3) | ... | T(N)
 *
 *         OKM = first L octets of T
 *
 *         T(0) = empty string (zero length)
 *
 *         T(1) = H(PRK, T(0) | info | 0x01)
 *
 *         T(2) = H(PRK, T(1) | info | 0x02)
 *
 *         T(3) = H(PRK, T(2) | info | 0x03)
 *
 *         ...
 *
 *         T(N) = H(PRK, T(N - 1) | info | N)
 *
 * @param[in] prk       The pseudorandom key to expand
 * @param[in] info      A pointer to the info
 * @param[in] info_len  The size of the info
 * @param[in] len       The desired size of the expanded key material
 *
 * @returns The expanded key material
 */
SecureBuffer expand(const SecureBuffer& prk,
                    const uint8_t* info,
                    const size_t info_len,
                    const size_t len);

} // namespace HkdfSha256

} // namespace crypto
} // namespace schwanenlied

#endif // SCHWANENLIED_CRYPTO_HKDF_SHA256_H__
