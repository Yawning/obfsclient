/**
 * @file    aes_ctr128.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   AES-CTR-128 (IMPLEMENTATION)
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
#include <cstring>

#include "schwanenlied/crypto/aes_ctr128.h"

namespace schwanenlied {
namespace crypto {

AesCtr128::~AesCtr128() {
  memwipe(&key_, sizeof(key_));
}

bool AesCtr128::set_state(const SecureBuffer& key,
                          const uint8_t* ctr,
                          const size_t ctr_len) {
  if (key.size() != kKeyLength)
    return false;
  if (ctr == nullptr)
    return false;
  if (ctr_len > kMaxCtrLength)
    return false;

  clear_state();

  // Setup the key
  if (0 != ::AES_set_encrypt_key(key.data(), kKeyLength * 8, &key_))
    return false;

  // Initialize the counter
  const size_t ctr_off = kMaxCtrLength - ctr_len;
  ::std::memcpy(&ctr_[ctr_off], ctr, ctr_len);

  has_state_ = true;

  return true;
}

void AesCtr128::clear_state() {
  if (has_state_) {
    ::std::fill(ctr_.begin(), ctr_.end(), 0);
    ::std::fill(block_.begin(), block_.end(), 0);
    offset_ = 0;
    memwipe(&key_, sizeof(key_));
    has_state_ = false;
  }
}

bool AesCtr128::process(const uint8_t* buf,
                        const size_t len,
                        uint8_t* out) {
  if (buf == nullptr)
    return false;
  if (len == 0)
    return false;
  if (out == nullptr)
    return false;
  if (!has_state_)
    return false;

  for (size_t i = len; i > 0; i--) {
    if (offset_ == 0) {
      ::AES_ecb_encrypt(ctr_.data(), &block_[0], &key_, AES_ENCRYPT);
      for (auto j = ctr_.rbegin(); j != ctr_.rend(); ++j)
        if (++*j != 0)
         break;
    }

    *out++ = (*buf++) ^ block_[offset_];
    offset_ = (offset_ + 1) & 0x0f;
  }

  return true;
}

} // namespace crypto
} // namespace schwanenlied
