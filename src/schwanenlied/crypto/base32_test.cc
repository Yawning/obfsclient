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
#include "gtest/gtest.h"

namespace schwanenlied {
namespace crypto {

class Base32Test : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

TEST_F(Base32Test, RFC4648_Test_1) {
  const uint8_t encoded[] = {
   'M', 'Y', '=', '=', '=', '=', '=', '='
  };
  const uint8_t decoded[] = { 'f' };

  SecureBuffer tmp;
  ASSERT_EQ(sizeof(decoded), Base32::decode(encoded, sizeof(encoded), tmp));
  ASSERT_EQ(0, tmp.compare(SecureBuffer(decoded, sizeof(decoded))));
}

TEST_F(Base32Test, RFC4648_Test_2) {
  const uint8_t encoded[] = {
   'M', 'Z', 'X', 'Q', '=', '=', '=', '='
  };
  const uint8_t decoded[] = { 'f', 'o' };

  SecureBuffer tmp;
  ASSERT_EQ(sizeof(decoded), Base32::decode(encoded, sizeof(encoded), tmp));
  ASSERT_EQ(0, tmp.compare(SecureBuffer(decoded, sizeof(decoded))));
}

TEST_F(Base32Test, RFC4648_Test_3) {
  const uint8_t encoded[] = {
   'M', 'Z', 'X', 'W', '6', '=', '=', '='
  };
  const uint8_t decoded[] = { 'f', 'o', 'o' };

  SecureBuffer tmp;
  ASSERT_EQ(sizeof(decoded), Base32::decode(encoded, sizeof(encoded), tmp));
  ASSERT_EQ(0, tmp.compare(SecureBuffer(decoded, sizeof(decoded))));
}

TEST_F(Base32Test, RFC4648_Test_4) {
  const uint8_t encoded[] = {
   'M', 'Z', 'X', 'W', '6', 'Y', 'Q', '='
  };
  const uint8_t decoded[] = { 'f', 'o', 'o', 'b' };

  SecureBuffer tmp;
  ASSERT_EQ(sizeof(decoded), Base32::decode(encoded, sizeof(encoded), tmp));
  ASSERT_EQ(0, tmp.compare(SecureBuffer(decoded, sizeof(decoded))));
}

TEST_F(Base32Test, RFC4648_Test_5) {
  const uint8_t encoded[] = {
   'M', 'Z', 'X', 'W', '6', 'Y', 'T', 'B'
  };
  const uint8_t decoded[] = { 'f', 'o', 'o', 'b', 'a' };

  SecureBuffer tmp;
  ASSERT_EQ(sizeof(decoded), Base32::decode(encoded, sizeof(encoded), tmp));
  ASSERT_EQ(0, tmp.compare(SecureBuffer(decoded, sizeof(decoded))));
}

TEST_F(Base32Test, RFC4648_Test_6) {
  const uint8_t encoded[] = {
   'M', 'Z', 'X', 'W', '6', 'Y', 'T', 'B', 'O', 'I',
   '=', '=', '=', '=', '=', '='
  };
  const uint8_t decoded[] = { 'f', 'o', 'o', 'b', 'a', 'r' };

  SecureBuffer tmp;
  ASSERT_EQ(sizeof(decoded), Base32::decode(encoded, sizeof(encoded), tmp));
  ASSERT_EQ(0, tmp.compare(SecureBuffer(decoded, sizeof(decoded))));
}

} // namespace crypto
} // namespace schwanenlied
