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

#include "schwanenlied/crypto/sha256.h"
#include "schwanenlied/crypto/utils.h"
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class Sha256Test : public ::testing::Test {
 protected:
  virtual void SetUp() {
    for (size_t i = 0; i < sizeof(omgLotsOfAs_); i++) {
      omgLotsOfAs_[i] = 'a';
    }
  }
  virtual void TearDown() {}

  uint8_t omgLotsOfAs_[1000000];
};

// Test vectors stolen from http://www.nsrl.nist.gov/testdata/

TEST_F(Sha256Test, NIST_NSRL_abc) {
  const uint8_t data[] = {
    'a', 'b', 'c'
  };
  const uint8_t expected[] = {
    // BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
  };

  Sha256 sha;
  uint8_t digest[Sha256::kDigestLength];

  ASSERT_TRUE(sha.digest(data, sizeof(data), digest, sizeof(digest)));
  ASSERT_EQ(0, memequals(expected, digest, sizeof(digest)));
}

TEST_F(Sha256Test, NIST_NSRL_abc_dot_dot_dot) {
  const uint8_t data[] = {
    'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e', 'c', 'd', 'e', 'f', 'd',
    'e', 'f', 'g', 'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i', 'g', 'h',
    'i', 'j', 'h', 'i', 'j', 'k', 'i', 'j', 'k', 'l', 'j', 'k', 'l',
    'm', 'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o', 'm', 'n', 'o', 'p',
    'n', 'o', 'p', 'q'
  };
  const uint8_t expected[] = {
    // 248D6A61 D20638B8 E5C02693 0C3E6039 A33CE459 64FF2167 F6ECEDD4 19DB06C1
    0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
    0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
    0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
    0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1
  };

  Sha256 sha;
  uint8_t digest[Sha256::kDigestLength];

  ASSERT_TRUE(sha.digest(data, sizeof(data), digest, sizeof(digest)));
  ASSERT_EQ(0, memequals(expected, digest, sizeof(digest)));
}

TEST_F(Sha256Test, NIST_NSRL_omgLotsOfAs) {
  const uint8_t expected[] = {
    // CDC76E5C 9914FB92 81A1C7E2 84D73E67 F1809A48 A497200E 046D39CC C7112CD0
    0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92,
    0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
    0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E,
    0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0
  };

  Sha256 sha;
  uint8_t digest[Sha256::kDigestLength];

  ASSERT_TRUE(sha.digest(omgLotsOfAs_, sizeof(omgLotsOfAs_), digest, sizeof(digest)));
  ASSERT_EQ(0, memequals(expected, digest, sizeof(digest)));
}

} // namespace crypto
} // namespace schwanenlied
