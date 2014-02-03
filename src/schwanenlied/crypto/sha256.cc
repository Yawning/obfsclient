/**
 * @file    sha256.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   SHA256 (IMPLEMENTATION)
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

#include <openssl/evp.h>

#include "schwanenlied/crypto/sha256.h"

namespace schwanenlied {
namespace crypto {

bool Sha256::digest(const uint8_t* buf,
                    const size_t len,
                    uint8_t* out,
                    const size_t out_len,
                    const int iters) const {
  if (buf == nullptr)
    return false;
  if (len == 0)
    return false;
  if (out == nullptr)
    return false;
  if (out_len != kDigestLength)
    return false;
  if (iters <= 0)
    return false;

  EVP_MD_CTX* ctx = ::EVP_MD_CTX_create();
  if (ctx == nullptr)
    return false;

  bool ret = false;
  unsigned int s = out_len;
  if (1 != ::EVP_DigestInit_ex(ctx, ::EVP_sha256(), NULL))
    goto out;
  if (1 != ::EVP_DigestUpdate(ctx, buf, len))
    goto out;
  if (1 != ::EVP_DigestFinal(ctx, out, &s))
    goto out;
  for (auto i = 1; i < iters; i++) {
    if (1 != ::EVP_DigestInit_ex(ctx, ::EVP_sha256(), NULL))
      goto out;
    if (1 != ::EVP_DigestUpdate(ctx, out, out_len))
      goto out;
    if (1 != ::EVP_DigestFinal(ctx, out, &s))
      goto out;
  }
  ret = true;

out:
  ::EVP_MD_CTX_destroy(ctx);
  return ret;
}

} // namespace crypto
} // namespace schwanenlied
