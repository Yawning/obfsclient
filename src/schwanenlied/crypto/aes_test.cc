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

#include <array>

#include "schwanenlied/crypto/aes.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class Aes128CtrTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

struct test_vector {
  uint8_t plaintext[16];
  uint8_t ciphertext[16];
};

TEST_F(Aes128CtrTest, SP800_38A_Encrypt) {
  // F.5.1
  // CTR-AES128.Encrypt
  // Key 2b7e151628aed2a6abf7158809cf4f3c
  const ::std::array<uint8_t, kAes128KeyLength> key = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };
  // Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  const ::std::array<uint8_t, 16> ctr = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  };
  const test_vector vectors[] = {
    // Block #1
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Output Block ec8cdf7398607cb0f2d21675ea9ea1e4
    // Plaintext 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext 874d6191b620e3261bef6864990db6ce
    {
      {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
      },
      {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
      }
    },

    // Block #2
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
    // Output Block 362b7c3c6773516318a077d7fc5073ae
    // Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
    // Ciphertext 9806f66b7970fdff8617187bb9fffdff
    {
      {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
      },
      {
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
        0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff
      }
    },

    // Block #3
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
    // Output Block 6a2cc3787889374fbeb4c81b17ba6c44
    // Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
    // Ciphertext 5ae4df3edbd5d35e5b4f09020db03eab
    {
      {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
      },
      {
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
        0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab
      }
    },

    // Block #4
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
    // Output Block e89c399ff0f198c6d40a31db156cabfe
    // Plaintext f69f2445df4f9b17ad2b417be66c3710
    // Ciphertext 1e031dda2fbe03d1792170a0f3009cee
    {
      {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
      },
      {
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
        0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
      }
    }
  };

  Aes128Ctr aes;
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));
  for (int i = 0; i < 4; i++) {
    uint8_t ct[16];
    ASSERT_TRUE(aes.process(vectors[i].plaintext,
                            sizeof(vectors[i].plaintext), ct));
    ASSERT_TRUE(memequals(ct, vectors[i].ciphertext, sizeof(ct)));
  }
}

TEST_F(Aes128CtrTest, SP800_38A_Decrypt) {
  // F.5.2
  // CTR-AES128.Decrypt
  // Key 2b7e151628aed2a6abf7158809cf4f3c
  const ::std::array<uint8_t, kAes128KeyLength> key = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };
  // Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  const ::std::array<uint8_t, 16> ctr = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  };
  const test_vector vectors[] = {
    // Block #1
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Output Block ec8cdf7398607cb0f2d21675ea9ea1e4
    // Ciphertext 874d6191b620e3261bef6864990db6ce
    // Plaintext 6bc1bee22e409f96e93d7e117393172a
    {
      {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
      },
      {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
      }
    },

    // Block #2
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
    // Output Block 362b7c3c6773516318a077d7fc5073ae
    // Ciphertext 9806f66b7970fdff8617187bb9fffdff
    // Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
    {
      {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
      },
      {
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
        0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff
      },
    },

    // Block #3
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
    // Output Block 6a2cc3787889374fbeb4c81b17ba6c44
    // Ciphertext 5ae4df3edbd5d35e5b4f09020db03eab
    // Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
    {
      {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
      },
      {
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
        0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab
      }
    },

    // Block #4
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
    // Output Block e89c399ff0f198c6d40a31db156cabfe
    // Ciphertext 1e031dda2fbe03d1792170a0f3009cee
    // Plaintext f69f2445df4f9b17ad2b417be66c3710
    {
      {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
      },
      {
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
        0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
      }
    }
  };

  Aes128Ctr aes;
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));
  for (int i = 0; i < 4; i++) {
    uint8_t pt[16];
    ASSERT_TRUE(aes.process(vectors[i].ciphertext,
                            sizeof(vectors[i].ciphertext), pt));
    ASSERT_TRUE(memequals(pt, vectors[i].plaintext, sizeof(pt)));
  }
}

} // namespace crypto
} // namespace schwanenlied
