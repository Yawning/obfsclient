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

class AesTest : public ::testing::Test {
 protected:
  virtual void SetUp() {}
  virtual void TearDown() {}
};

struct test_vector {
  uint8_t plaintext[16];
  uint8_t ciphertext[16];
};

/*
 * Test vectors taken from NIST SP 800-38A
 *  * Validate the base OpenSSL AES implementation.
 *  * Validate CTR mode works, at least with a 128 bit CTR
 */

TEST_F(AesTest, CtrAes128_SP800_38A) {
  // F.5.1/F.5.2
  // CTR-AES128.Encrypt/CTR-AES128.Decrypt

  // Key 2b7e151628aed2a6abf7158809cf4f3c
  const ::std::array<uint8_t, kAes128KeyLength> key = { {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  } };

  // Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  const ::std::array<uint8_t, 16> ctr = { {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  } };

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

  // Encrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));

  for (int i = 0; i < 4; i++) {
    uint8_t ct[16];
    ASSERT_TRUE(aes.process(vectors[i].plaintext,
                            sizeof(vectors[i].plaintext), ct));
    ASSERT_TRUE(memequals(ct, vectors[i].ciphertext, sizeof(ct)));
  }

  // Decrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));
  for (int i = 0; i < 4; i++) {
    uint8_t pt[16];
    ASSERT_TRUE(aes.process(vectors[i].ciphertext,
                            sizeof(vectors[i].ciphertext), pt));
    ASSERT_TRUE(memequals(pt, vectors[i].plaintext, sizeof(pt)));
  }

}

TEST_F(AesTest, CtrAes192_SP800_38A) {
  // F.5.3/F.5.4
  // CTR-AES192.Encrypt/CTR-AES192.Decrypt

  // Key 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
  const ::std::array<uint8_t, kAes192KeyLength> key = { {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
  } };

  // Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  const ::std::array<uint8_t, 16> ctr = { {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  } };

  const test_vector vectors[] = {
    // Block #1
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Output Block 717d2dc639128334a6167a488ded7921
    // Plaintext 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext 1abc932417521ca24f2b0459fe7e6e0b
    {
      {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
      },
      {
        0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
        0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b
      }
    },

    // Block #2
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
    // Output Block a72eb3bb14a556734b7bad6ab16100c5
    // Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
    // Ciphertext 090339ec0aa6faefd5ccc2c6f4ce8e94
    {
      {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
      },
      {
        0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef,
        0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94
      }
    },

    // Block #3
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
    // Output Block 2efeae2d72b722613446dc7f4c2af918
    // Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
    // Ciphertext 1e36b26bd1ebc670d1bd1d665620abf7
    {
      {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
      },
      {
        0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70,
        0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7
      }
    },

    // Block #4
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
    // Output Block b9e783b30dd7924ff7bc9b97beaa8740
    // Plaintext f69f2445df4f9b17ad2b417be66c3710
    // Ciphertext 4f78a7f6d29809585a97daec58c6b050 
    {
      {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
      },
      {
        0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58,
        0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50 
      }
    }
  };

  Aes192Ctr aes;

  // Encrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));

  for (int i = 0; i < 4; i++) {
    uint8_t ct[16];
    ASSERT_TRUE(aes.process(vectors[i].plaintext,
                            sizeof(vectors[i].plaintext), ct));
    ASSERT_TRUE(memequals(ct, vectors[i].ciphertext, sizeof(ct)));
  }

  // Decrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));
  for (int i = 0; i < 4; i++) {
    uint8_t pt[16];
    ASSERT_TRUE(aes.process(vectors[i].ciphertext,
                            sizeof(vectors[i].ciphertext), pt));
    ASSERT_TRUE(memequals(pt, vectors[i].plaintext, sizeof(pt)));
  }
}

TEST_F(AesTest, CtrAes256_SP800_38A) {
  // F.5.5/F.5.6
  // CTR-AES256.Encrypt/CTR-AES256.Decrypt

  // Key 603deb1015ca71be2b73aef0857d7781
  //     1f352c073b6108d72d9810a30914dff4
  const ::std::array<uint8_t, kAes256KeyLength> key = { {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  } };

  // Init. Counter f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  const ::std::array<uint8_t, 16> ctr = { {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
  } };
  const test_vector vectors[] = {
    // Block #1
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Output Block 0bdf7df1591716335e9a8b15c860c502
    // Plaintext 6bc1bee22e409f96e93d7e117393172a
    // Ciphertext 601ec313775789a5b7a7f504bbf3d228
    {
      {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
      },
      {
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
        0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28
      }
    },

    // Block #2
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff00
    // Output Block 5a6e699d536119065433863c8f657b94
    // Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
    // Ciphertext f443e3ca4d62b59aca84e990cacaf5c5
    {
      {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
      },
      {
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
        0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5
      }
    },

    // Block #3
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff01
    // Output Block 1bc12c9c01610d5d0d8bd6a3378eca62
    {
      {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
      },
      {
        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
        0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d
      }
    },

    // Block #4
    // Input Block f0f1f2f3f4f5f6f7f8f9fafbfcfdff02
    // Output Block 2956e1c8693536b1bee99c73a31576b6
    // Plaintext f69f2445df4f9b17ad2b417be66c3710
    // Ciphertext dfc9c58db67aada613c2dd08457941a6
    {
      {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
      },
      {
        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
        0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
      }
    },
  };

  Aes256Ctr aes;

  // Encrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));

  for (int i = 0; i < 4; i++) {
    uint8_t ct[16];
    ASSERT_TRUE(aes.process(vectors[i].plaintext,
                            sizeof(vectors[i].plaintext), ct));
    ASSERT_TRUE(memequals(ct, vectors[i].ciphertext, sizeof(ct)));
  }

  // Decrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()), nullptr, 0,
                            ctr.data(), ctr.size()));
  for (int i = 0; i < 4; i++) {
    uint8_t pt[16];
    ASSERT_TRUE(aes.process(vectors[i].ciphertext,
                            sizeof(vectors[i].ciphertext), pt));
    ASSERT_TRUE(memequals(pt, vectors[i].plaintext, sizeof(pt)));
  }
}

/*
 * Test Vectors taken from RFC 3686
 *  * Validate that nonce + CTR style CTR-AES mode works. (Nonce + IV + CTR)
 *
 * Note:
 * Only CTR-AES-128 is tested since the code is common (the difference is 2
 * template parameters denoting the OpenSSL EVP_CIPHER and the key size).
 */

TEST_F(AesTest, RFC3686_Test_1) {
  // Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key

  // AES Key          : AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E
  const ::std::array<uint8_t, kAes128KeyLength> key = { {
    0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC,
    0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E
  } };

  // AES-CTR IV       : 00 00 00 00 00 00 00 00
  // Nonce            : 00 00 00 30
  const ::std::array<uint8_t, 12> nonce_iv = { {
    0x00, 0x00, 0x00, 0x30,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  } };

  const ::std::array<uint8_t, 4> ctr = { {
    0x00, 0x00, 0x00, 0x01
  } };

  // Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
  const ::std::array<uint8_t, 16> plaintext = { {
    0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
    0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67
  } };

  // Ciphertext       : E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8
  const ::std::array<uint8_t, 16> ciphertext = { {
    0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
    0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8
  } };

  Aes128Ctr aes;

  // Encrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()),
                            nonce_iv.data(), nonce_iv.size(),
                            ctr.data(), ctr.size()));

  uint8_t ct[ciphertext.size()];
  ASSERT_TRUE(aes.process(plaintext.data(), plaintext.size(), ct));
  ASSERT_TRUE(memequals(ct, ciphertext.data(), ciphertext.size()));
}

TEST_F(AesTest, RFC3686_Test_2) {
  // Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key

  // AES Key          : 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63
  const ::std::array<uint8_t, kAes128KeyLength> key = { {
    0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
    0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63
  } };

  // AES-CTR IV       : C0 54 3B 59 DA 48 D9 0B
  // Nonce            : 00 6C B6 DB
  const ::std::array<uint8_t, 12> nonce_iv = { {
    0x00, 0x6C, 0xB6, 0xDB,
    0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B
  } };

  const ::std::array<uint8_t, 4> ctr = { {
    0x00, 0x00, 0x00, 0x01
  } };

  // Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
  //                  : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
  const ::std::array<uint8_t, 32> plaintext = { {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  } };

  // Ciphertext       : 51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88
  //                  : EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28
  const ::std::array<uint8_t, 32> ciphertext = { {
    0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
    0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
    0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
    0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28
  } };

  Aes128Ctr aes;

  // Encrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()),
                            nonce_iv.data(), nonce_iv.size(),
                            ctr.data(), ctr.size()));

  uint8_t ct[ciphertext.size()];
  ASSERT_TRUE(aes.process(plaintext.data(), plaintext.size(), ct));
  ASSERT_TRUE(memequals(ct, ciphertext.data(), ciphertext.size()));
}

TEST_F(AesTest, RFC3686_Test_3) {
  // Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key

  // AES Key          : 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC
  const ::std::array<uint8_t, kAes128KeyLength> key = { {
    0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8,
    0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC
  } };

  // AES-CTR IV       : 27 77 7F 3F  4A 17 86 F0
  // Nonce            : 00 E0 01 7B
  const ::std::array<uint8_t, 12> nonce_iv = { {
    0x00, 0xE0, 0x01, 0x7B,
    0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0
  } };

  const ::std::array<uint8_t, 4> ctr = { {
    0x00, 0x00, 0x00, 0x01
  } };

  // Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
  //                  : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
  //                  : 20 21 22 23
  const ::std::array<uint8_t, 36> plaintext = { {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23
  } };

  // Ciphertext       : C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7
  //                  : 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53
  //                  : 25 B2 07 2F
  const ::std::array<uint8_t, 36> ciphertext = { {
    0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9,
    0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
    0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
    0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
    0x25, 0xB2, 0x07, 0x2F
  } };

  Aes128Ctr aes;

  // Encrypt
  ASSERT_TRUE(aes.set_state(SecureBuffer(key.data(), key.size()),
                            nonce_iv.data(), nonce_iv.size(),
                            ctr.data(), ctr.size()));

  uint8_t ct[ciphertext.size()];
  ASSERT_TRUE(aes.process(plaintext.data(), plaintext.size(), ct));
  ASSERT_TRUE(memequals(ct, ciphertext.data(), ciphertext.size()));
}

} // namespace crypto
} // namespace schwanenlied
