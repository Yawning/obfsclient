/**
 * @file    obfs3client.h
 * @author  Yawning Angel (yawning at schwanenlied dot me)
 * @brief   obfs3 (The Threebfuscator) Client
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

#ifndef SCHWANENLIED_PT_OBFS3CLIENT_H__
#define SCHWANENLIED_PT_OBFS3CLIENT_H__

#include "schwanenlied/common.h"
#include "schwanenlied/socks4_server.h"
#include "schwanenlied/crypto/aes_ctr128.h"
#include "schwanenlied/crypto/hmac_sha256.h"
#include "schwanenlied/crypto/uniform_dh.h"

namespace schwanenlied {
namespace pt {

/**
 * obfs3 (The Threebfuscator) Client
 *
 * This implements a wire compatible obfs3 client using Socks4Server.
 *
 * @todo Investigate using evbuffer_peek()/evbuffer_add_buffer() for better
 * performance (current code is more obviously correct).
 */
class Obfs3Client : public Socks4Server::Session {
 public:
  /** Obfs3Client factory */
  class SessionFactory : public Socks4Server::SessionFactory {
   public:
    Socks4Server::Session* create_session(struct event_base* base,
                                          const evutil_socket_t sock,
                                          const struct sockaddr* addr,
                                          const int addr_len) override {
      return new Obfs3Client(base, sock, addr, addr_len);
    }
  };

  Obfs3Client(struct event_base* base,
              const evutil_socket_t sock,
              const struct sockaddr* addr,
              const int addr_len) :
      Session(base, sock, addr, addr_len),
      sent_magic_(false),
      received_magic_(false),
      initiator_magic_(crypto::HmacSha256::kDigestLength, 0),
      responder_magic_(crypto::HmacSha256::kDigestLength, 0) {}

  ~Obfs3Client() = default;

 protected:
  void on_outgoing_connected() override;

  void on_incoming_data() override;

  void on_incoming_drained() override;

  void on_outgoing_data_connecting() override;

  void on_outgoing_data() override;

  void on_outgoing_drained() override;

 private:
  Obfs3Client(const Obfs3Client&) = delete;
  void operator=(const Obfs3Client&) = delete;

  static const uint16_t kMaxPadding = 8194; /** obfs3 MAX_PADDING */

  /** @{ */
  /**
   * Given a shared secret, derive the AES-CTR-128 keys per the obfs3 spec
   *
   * @param shared_secret The shared secret to use as the key material
   *
   * @returns true  - Success
   * @returns false - Failure
   */
  bool kdf_obfs3(const crypto::SecureBuffer& shared_secret);

  /** Generate PADLEN (or PADLEN2) per the obfs3 spec */
  uint16_t gen_padlen() const;
  /** @} */

  /** @{ */
  crypto::UniformDH uniform_dh_;    /**< The UniformDH keypair */
  crypto::AesCtr128 initiator_aes_; /**< E(INIT_KEY, DATA) */
  crypto::AesCtr128 responder_aes_; /**< E(RESP_KEY, DATA) */
  /** @} */

  /** @{ */
  bool sent_magic_;     /**< Sent initator_magic_ to the peer? */
  bool received_magic_; /**< Received responder_magic_ from the peer? */
  crypto::SecureBuffer initiator_magic_; /**< HMAC(SHARED_SECRET, "Initiator magic") */
  crypto::SecureBuffer responder_magic_; /**< HMAC(SHARED_SECRET, "Responder magic") */
  /** @} */
};

} // namespace pt
} // namespace schwanenlied

#endif // SCHWANENLIED_PT_OBFS3CLIENT_H__
