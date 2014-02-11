/**
 * @file    hkdf_sha256.cc
 * @author  Yawning Angel
 * @brief   HKDF-SHA256 (IMPLEMENTATION)
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

#include <algorithm>
#include <array>
#include <cstring>

#include "schwanenlied/crypto/hkdf_sha256.h"

namespace schwanenlied {
namespace crypto {
namespace HkdfSha256 {

SecureBuffer extract(const uint8_t* salt,
                     const size_t salt_len,
                     const SecureBuffer& ikm) {
  HmacSha256 h;
  SecureBuffer prk(HmacSha256::kDigestLength, 0);
  bool ret = true;

  if (salt == nullptr) {
    SL_ASSERT(salt_len == 0);
    const ::std::array<uint8_t, HmacSha256::kDigestLength> zero_salt = { 0 };
    ret &= h.set_key(SecureBuffer(zero_salt.data(), zero_salt.size()));
  } else
    ret &= h.set_key(SecureBuffer(salt, salt_len));

  ret &= h.digest(ikm.data(), ikm.size(), &prk[0], prk.size());
  SL_ASSERT(ret);

  return prk;
}

SecureBuffer expand(const SecureBuffer& prk,
                    const uint8_t* info,
                    const size_t info_len,
                    const size_t len) {
  SL_ASSERT(prk.length() >= HmacSha256::kDigestLength);

  size_t n = (len + HmacSha256::kDigestLength - 1) / HmacSha256::kDigestLength;
  SL_ASSERT(n <= 255);

  ::std::array<uint8_t, HmacSha256::kDigestLength> t;
  HmacSha256 h(prk);
  SecureBuffer okm(len, 0);
  uint8_t* p = &okm[0];
  size_t remaining = len;

  for (uint8_t i = 1; i <= n; i++) {
    size_t to_copy = ::std::min(remaining, t.size());
    bool ret = h.init();
    if (i > 1)
      ret &= h.update(t.data(), t.size());
    ret &= h.update(info, info_len);
    ret &= h.update(&i, sizeof(i));
    ret &= h.final(t.data(), t.size());
    SL_ASSERT(ret);
    ::std::memcpy(p, t.data(), to_copy);
    p += to_copy;
    remaining -= to_copy;
  }

  memwipe(t.data(), t.size());

  return okm;
}

} // namespace HkdfSha256
} // namespace crypto
} // namespace schwanenlied
