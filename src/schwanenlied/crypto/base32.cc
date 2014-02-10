/**
 * @file    base32.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   Base32 Decoder (IMPLEMENTATION)
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

#include "schwanenlied/crypto/base32.h"

namespace schwanenlied {
namespace crypto {

namespace Base32 {

size_t decode(const uint8_t* buf,
              const size_t len,
              SecureBuffer& dst) {
  dst.clear();
  dst.resize(len * 5 / 8, 0); 

  auto conv_char = [](const uint8_t c) -> uint8_t {
    if (c >= 'A' && c <= 'Z')
      return c - 'A';
    else if (c >= '2' && c <= '7')
      return c - '2' + 26;
    else
      return 0xff;
  };

  int index = 0;
  size_t offset = 0;
  for (size_t i = 0; i < len; i ++) {
    uint8_t c = conv_char(buf[i]);
    if (c == 0xff)
      break;

    if (index <= 3) {
      index = (index + 5) & 0x07;
      if (index == 0) {
        dst[offset] |= c;
        offset++;
        if (offset >= dst.size())
          break;
      } else
        dst[offset] |= c << (8 - index);
    } else {
      index = (index + 5) & 0x07;
      dst[offset] |= (c >> index);
      offset++;
      if (offset >= dst.size()) {
        break;
      }
      dst[offset] |= c << (8 - index);
    }
  }

  dst.resize(offset);
  return offset;
}

} // namespace Base32

} // namespace crpto
} // namespace schwanenlied
