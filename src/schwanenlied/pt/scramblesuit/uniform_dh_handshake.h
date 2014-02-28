/**
 * @file    uniform_dh_handshake.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   ScrambleSuit UniformDH Handshake
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

#ifndef SCHWANENLIED_PT_SCRAMBLESUIT_UNIFORM_DH_HANDSHAKE_H__
#define SCHWANENLIED_PT_SCRAMBLESUIT_UNIFORM_DH_HANDSHAKE_H__

#include "schwanenlied/common.h"
#include "schwanenlied/crypto/hmac_sha256.h"
#include "schwanenlied/crypto/sha256.h"
#include "schwanenlied/crypto/uniform_dh.h"
#include "schwanenlied/crypto/utils.h"

namespace schwanenlied {
namespace pt {
namespace scramblesuit {

class Client;

/**
 * Implement the client side of the ScrambleSuit UniformDH Handshake
 */
class UniformDHHandshake {
 public:
  /**
   * Construct a new UniformDHHandshake instance
   *
   * @param[in] client        The Client instance
   * @param[in] shared_secret The bridge secret (k_B)
   */
  UniformDHHandshake(Client& client,
                     const crypto::SecureBuffer& shared_secret) :
      client_(client),
      hmac_(shared_secret) {}

  ~UniformDHHandshake() = default;

  /** @{ */
  /**
   * Send the outgoing side of the handshake
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool send_handshake_msg();

  /**
   * Recieve the handshake response from a bridge
   *
   * In addition to checking the return value, applications must examine
   * is_finished to see if the handshake process is actually done.  A shared
   * secret is available only when this routine returns true *and* is_finished
   * is true. 
   *
   * @param[out] is_finished  Did the handshake complete?
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool recv_handshake_msg(bool& is_finished);
  /** @} */

 private:
  UniformDHHandshake() = delete;
  UniformDHHandshake(const UniformDHHandshake&) = delete;
  void operator=(const UniformDHHandshake&) = delete;

  /** The length of the resultant shared secret */
  static constexpr size_t kSharedSecretLength = crypto::Sha256::kDigestLength;
  /** The UniformDH public key length (X, Y) */
  static constexpr size_t kKeyLength = crypto::UniformDH::kKeyLength;
  /** The HMAC-SHA-256 digest length (M_C, M_S, MAC) */
  static constexpr size_t kDigestLength = 16;
  /** The maximum allowed padding length (P_C, P_S) */
  static constexpr size_t kMaxPadding = 1308;
  /** The maximum allowed total handshake message length */
  static constexpr size_t kMaxMsgLength = kKeyLength + kMaxPadding +
      kDigestLength * 2;

  /** Generate pad length suitable for P_C */
  uint16_t gen_padlen() const;

  /** The Client instance that the handshake is for */
  Client& client_;
  /** The remote peer's public UniformDH key */
  ::std::unique_ptr<crypto::SecureBuffer> remote_public_key_;
  /** The derived M_S */
  ::std::unique_ptr<crypto::SecureBuffer> remote_mark_;
  /** The derived MAC(Y | P_S | M_S | E) */
  ::std::unique_ptr<crypto::SecureBuffer> remote_mac_;
  /** The number of hours since the epoch */
  ::std::string epoch_hour_;

  crypto::UniformDH uniform_dh_;  /**< The UniformDH instance */
  crypto::HmacSha256 hmac_;       /**< The HMAC-SHA256-128 instance */
};

} // namespace scramblesuit
} // namespace pt
} // namespace schwanenlied

#endif // SCHWANENLIED_PT_SCRAMBLESUIT_UNIFORMDH_HANDSHAKE_H__
