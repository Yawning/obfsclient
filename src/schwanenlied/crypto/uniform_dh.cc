/**
 * @file    uniform_dh.cc
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   UniformDH Key Exchange (IMPLEMENTATION)
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

#include <mutex>

#include "schwanenlied/crypto/uniform_dh.h"

namespace schwanenlied {
namespace crypto {

static ::std::once_flag load_params;

static const unsigned char rfc3526_group_5_p[] = {
  // FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
  0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,

  // 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
  0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  
  // EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
  0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  
  // E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
  0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  
  // EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
  0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
  
  // C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
  0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
  0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
 
  // 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
  0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
  0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,

  // 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
  0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
  0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char rfc3526_group_5_g[] = {
 0x02
};

static BIGNUM* uniform_dh_p = nullptr;
static BIGNUM* uniform_dh_g = nullptr;

UniformDH::UniformDH() :
    ctx_(::BN_CTX_new()),
    private_key_(::BN_new()),
    public_key_(kKeySz, 0),
    has_shared_secret_(false),
    shared_secret_(kKeySz, 0) {
  SL_ASSERT(private_key_ != nullptr);
  SL_ASSERT(ctx_ != nullptr);  

  // Load the UniformDH MODP group
  ::std::call_once(load_params, []() {
    uniform_dh_p = ::BN_bin2bn(rfc3526_group_5_p, sizeof(rfc3526_group_5_p),
                               NULL);
    uniform_dh_g = ::BN_bin2bn(rfc3526_group_5_g, sizeof(rfc3526_group_5_g),
                               NULL);
    SL_ASSERT(uniform_dh_p != nullptr);
    SL_ASSERT(uniform_dh_g != nullptr);
  });

  /*
   * To pick a private UniformDH key, we pick a random 1536-bit number,
   * and make it even by setting its low bit to 0. Let x be that private
   * key, and X = g^x (mod p).
   */

  int ret = ::BN_rand(private_key_, kKeySz * 8, -1, 0);
  SL_ASSERT(ret == 1);
  const bool is_odd = BN_is_odd(private_key_);
  ret = ::BN_clear_bit(private_key_, 0);
  SL_ASSERT(ret == 1);

  // Calculate X = g^x (mod p)
  BIGNUM* pub_key = ::BN_new();
  SL_ASSERT(pub_key != nullptr);
  ret = ::BN_mod_exp(pub_key, uniform_dh_g, private_key_, uniform_dh_p,
                     ctx_);
  SL_ASSERT(ret == 1);
  if (is_odd) {
    // Calculate X = p - X
    BIGNUM* p_sub_X  = ::BN_new();
    SL_ASSERT(p_sub_X != nullptr);
    ret = ::BN_sub(p_sub_X, uniform_dh_p, pub_key);
    SL_ASSERT(ret == 1);
    BN_free(pub_key);
    pub_key = p_sub_X;
  }

  // Only need the public key that's going to be sent
  const int offset = public_key_.size() - BN_num_bytes(pub_key);
  ret = ::BN_bn2bin(pub_key, reinterpret_cast<unsigned
                    char*>(&public_key_[offset]));
  SL_ASSERT(ret + offset == kKeySz); 

  BN_free(pub_key);
}

UniformDH::~UniformDH() {
  BN_CTX_free(ctx_);
  if (private_key_ != nullptr)
    BN_free(private_key_);
}

bool UniformDH::compute_key(const uint8_t* pub_key,
                            const size_t len) {
  if (pub_key == nullptr)
    return false;
  if (len != kKeySz)
    return false;
  SL_ASSERT(has_shared_secret_ == false);

  BIGNUM* peer_public_key = ::BN_bin2bn(pub_key, len, NULL);
  if (peer_public_key == nullptr)
    return false;

  /*
   * When a party wants to calculate the shared secret, she
   * raises the foreign public key to her private key. Note that both
   * (p-Y)^x = Y^x (mod p) and (p-X)^y = X^y (mod p), since x and y are
   * even.
   *
   * Notes:
   *  * The spec says to just raise it, but the obfsproxy code does
   *    Y^x (mod p).
   *  * This is nothing even vaguely resembling constant time, but
   *    neither is obfsproxy.  This *should* use BN_BLINDING, however all of the
   *    encryption used for obfs3 is "as an obfuscation mechanism".  Someone
   *    running a timing attack to extract the keys means that we've lost
   *    already.
   */

  BIGNUM* secret = ::BN_new();
  SL_ASSERT(secret != nullptr);
  int ret = ::BN_mod_exp(secret, peer_public_key, private_key_, uniform_dh_p,
                         ctx_);
  if (ret == 1) {
    const int offset = shared_secret_.size() - BN_num_bytes(secret);
    ret = ::BN_bn2bin(secret, reinterpret_cast<unsigned
                      char*>(&shared_secret_[offset]));
    SL_ASSERT(ret + offset == kKeySz);
    BN_free(private_key_);
    private_key_ = nullptr;
    has_shared_secret_ = true;
  }

  BN_free(secret);
  BN_free(peer_public_key);

  return has_shared_secret_;
}

} // namespace crypto
} // namespace schwanenlied
