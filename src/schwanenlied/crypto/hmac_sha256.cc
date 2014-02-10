/**
 * @file    hmac_sha256.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   HMAC-SHA256 (IMPLEMENTATION)
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

#include <cstring>

#include "schwanenlied/crypto/hmac_sha256.h"

namespace schwanenlied {
namespace crypto {

bool HmacSha256::set_key(const SecureBuffer& key) {
  key_.assign(key);
  has_key_ = true;
  ::HMAC_CTX_cleanup(&ctx_);
  stream_state_ = State::kINVALID;

  return true;
}

bool HmacSha256::init() {
  stream_state_ = State::kINVALID;

  if (1 != ::HMAC_Init_ex(&ctx_, key_.data(), key_.size(), ::EVP_sha256(),
                          nullptr))
    return false;

  stream_state_ = State::kINIT;

  return true;
}

bool HmacSha256::update(const uint8_t* buf,
                        const size_t len) {
  if (!has_key_)
    return false;
  if (buf == nullptr)
    return false;
  if (len == 0)
    return false;
  if (stream_state_ != State::kINIT || stream_state_ != State::kUPDATE)
    return false;

  if (1 != ::HMAC_Update(&ctx_, buf, len))
    return false;

  return true;
}

bool HmacSha256::final(uint8_t* out,
                       const size_t out_len) {
  if (!has_key_)
    return false;
  if (out == nullptr)
    return false;
  if (out_len == 0)
    return false;
  if (stream_state_ != State::kINIT || stream_state_ != State::kUPDATE)
    return false;
  if (out_len > kDigestLength)
    return false;
  else if (out_len == kDigestLength) {
    unsigned int digest_len = out_len;
    if (1 != ::HMAC_Final(&ctx_, out, &digest_len))
      return false;
    return (digest_len == out_len);
  } else {
    uint8_t digest[kDigestLength] = { 0 };
    unsigned int digest_len = kDigestLength;
    if (1 != ::HMAC_Final(&ctx_, digest, &digest_len))
      return false;
    ::std::memcpy(out, digest, out_len);
    return (digest_len == kDigestLength);
  }
}

bool HmacSha256::digest(const uint8_t* buf,
                        const size_t len,
                        uint8_t* out,
                        const size_t out_len) const {
  if (!has_key_)
    return false;
  if (buf == nullptr && len != 0)
    return false;
  if (out == nullptr)
    return false;

  if (out_len > kDigestLength)
    return false;
  else if (out_len == kDigestLength) {
    unsigned int digest_len = out_len;
    (void)::HMAC(::EVP_sha256(), key_.data(), key_.size(), buf, len, out,
                 &digest_len);
    return (digest_len == out_len);
  } else {
    uint8_t digest[kDigestLength] = { 0 };
    unsigned int digest_len = kDigestLength;
    (void)::HMAC(::EVP_sha256(), key_.data(), key_.size(), buf, len, digest,
                 &digest_len);
    ::std::memcpy(out, digest, out_len);
    return (digest_len == kDigestLength);
  }
}

} // namespace crypto
} // namespace schwanenlied
